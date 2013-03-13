##! A module for executing external command line programs.
##! This requires code that is still in topic branches and 
##! definitely won't currently work on any released version of Bro.

@load base/frameworks/input

module Exec;

export {
	type Command: record {
		## The command line to execute.
		## Use care to avoid injection attacks!
		cmd:         string;
		## Provide standard in to the program as a
		## string.
		stdin:       string      &default="";
		## If additional files are required to be read 
		## in as part of the output of the command they
		## can be defined here.
		read_files:  set[string] &optional;
	};

	type Result: record {
		## Exit code from the program.
		exit_code:    count            &default=0;
		## Each line of standard out.
		stdout:       vector of string &optional;
		## Each line of standard error. 
		stderr:       vector of string &optional;
		## If additional files were requested to be read in
		## the content of the files will be available here.
		files:        table[string] of string_vec &optional;
	};

	## Function for running command line programs and getting
	## output.  This is an asynchronous function which is meant 
	## to be run with the `when` statement.
	##
	## cmd: The command to run.  Use care to avoid injection attacks!
	##
	## returns: A record representing the full results from the
	##          external program execution.
	global run: function(cmd: Command): Result;
}

redef record Command += {
	# The prefix name for tracking temp files.
	prefix_name: string &optional;
};

global results: table[string] of Result = table();
global finished_commands: set[string];
global tmp_files: set[string] = set();

type OneLine: record { line: string; };

event Exec::stdout_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	local result = results[name];
	if ( ! results[name]?$stdout )
		result$stdout = vector(s);
	else
		result$stdout[|result$stdout|] = s;
	}

event Exec::stderr_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	local result = results[name];
	if ( ! results[name]?$stderr )
		result$stderr = vector(s);
	else
		result$stderr[|result$stderr|] = s;
	}

event Exec::file_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local parts = split1(description$name, /_/);
	local name = parts[1];
	local track_file = parts[2];

	local result = results[name];
	if ( ! result?$files )
		result$files = table();
	
	if ( track_file !in result$files )
		result$files[track_file] = vector(s);
	else
		result$files[track_file][|result$files[track_file]|] = s;
	}

event Exec::cleanup_and_do_callback(name: string)
	{
	Input::remove(fmt("%s_stdout", name));
	system(fmt("rm %s_stdout", name));
	delete tmp_files[fmt("%s_stdout", name)];

	Input::remove(fmt("%s_stderr", name));
	system(fmt("rm %s_stderr", name));
	delete tmp_files[fmt("%s_stderr", name)];

	Input::remove(fmt("%s_done", name));
	system(fmt("rm %s_done", name));
	delete tmp_files[fmt("%s_done", name)];

	# Indicate to the "when" async watcher that this command is done.
	add finished_commands[name];
	}

event Exec::run_done(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local name = sub(description$name, /_[^_]*$/, "");

	if ( /^exit_code:/ in s )
		results[name]$exit_code = to_count(split1(s, /:/)[2]);
	else if ( s == "done" )
		# Wait one second to allow all threads to read all of their input
		# and forward it.
		schedule 1sec { Exec::cleanup_and_do_callback(name) };
	}

event Exec::start_watching_files(cmd: Command)
	{
	Input::add_event([$source=fmt("%s_done", cmd$prefix_name),
	                  $name=fmt("%s_done", cmd$prefix_name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::run_done]);

	Input::add_event([$source=fmt("%s_stdout", cmd$prefix_name),
	                  $name=fmt("%s_stdout", cmd$prefix_name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::stdout_line]);

	Input::add_event([$source=fmt("%s_stderr", cmd$prefix_name),
	                  $name=fmt("%s_stderr", cmd$prefix_name),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=OneLine,
	                  $ev=Exec::stderr_line]);

	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			{
			Input::add_event([$source=fmt("%s", read_file),
			                  $name=fmt("%s_%s", cmd$prefix_name, read_file),
			                  $reader=Input::READER_RAW,
			                  $mode=Input::STREAM,
			                  $want_record=F,
			                  $fields=OneLine,
			                  $ev=Exec::file_line]);
			}
		}
	}

function run(cmd: Command): Result
	{
	cmd$prefix_name = "/tmp/bro-exec-" + unique_id("");
	system(fmt("touch %s_done %s_stdout %s_stderr 2>/dev/null", cmd$prefix_name, cmd$prefix_name, cmd$prefix_name));
	add tmp_files[fmt("%s_done", cmd$prefix_name)];
	add tmp_files[fmt("%s_stdout", cmd$prefix_name)];
	add tmp_files[fmt("%s_stderr", cmd$prefix_name)];

	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			{
			system(fmt("touch %s 2>/dev/null", read_file));
			add tmp_files[read_file];
			}
		}

	piped_exec(fmt("%s 2>> %s_stderr 1>> %s_stdout; echo \"exit_code:${?}\" >> %s_done; echo \"done\" >> %s_done", 
	               cmd$cmd, cmd$prefix_name, cmd$prefix_name, cmd$prefix_name, cmd$prefix_name),
	           cmd$stdin);

	results[cmd$prefix_name] = [];

	schedule 1msec { Exec::start_watching_files(cmd) };

	return when ( cmd$prefix_name in finished_commands )
		{
		delete finished_commands[cmd$prefix_name];
		local result = results[cmd$prefix_name];
		delete results[cmd$prefix_name];
		return result;
		}
	}

event bro_done()
	{
	# We are punting here and just deleting any files that haven't been processed yet.
	for ( fname in tmp_files )
		{
		system(fmt("rm \"%s\"", str_shell_escape(fname)));
		}
	}