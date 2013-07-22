##! A module for executing external command line programs.

@load base/frameworks/input

module Exec;

export {
	type Command: record {
		## The command line to execute.  Use care to avoid injection attacks.
		## I.e. if the command uses untrusted/variable data, sanitize it.
		cmd:         string;
		## Provide standard in to the program as a string.
		stdin:       string      &default="";
		## If additional files are required to be read in as part of the output
		## of the command they can be defined here.
		read_files:  set[string] &optional;
	};

	type Result: record {
		## Exit code from the program.
		exit_code:    count            &default=0;
		## True if the command was terminated with a signal.
		signal_exit:  bool             &default=F;
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

	## The system directory for temp files.
	const tmp_dir = "/tmp" &redef;
}

redef record Command += {
	# The unique id for tracking executors.
	uid: string &optional;
};

global results: table[string] of Result = table();
global finished_commands: set[string];
global currently_tracked_files: set[string] = set();
type OneLine: record {
	s: string;
	is_stderr: bool;
};

type FileLine: record {
	s: string;
};

event Exec::line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	local result = results[description$name];
	if ( is_stderr )
		{
		if ( ! result?$stderr )
			result$stderr = vector(s);
		else
			result$stderr[|result$stderr|] = s;
		}
	else
		{
		if ( ! result?$stdout )
			result$stdout = vector(s);
		else
			result$stdout[|result$stdout|] = s;
		}
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

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	results[name]$exit_code = exit_code;
	results[name]$signal_exit = signal_exit;

	Input::remove(name);
	# Indicate to the "when" async watcher that this command is done.
	add finished_commands[name];
	}

event Exec::start_watching_file(uid: string, read_file: string)
	{
	Input::add_event([$source=fmt("%s", read_file),
	                  $name=fmt("%s_%s", uid, read_file),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $want_record=F,
	                  $fields=FileLine,
	                  $ev=Exec::file_line]);
	}

function run(cmd: Command): Result
	{
	cmd$uid = unique_id("");
	results[cmd$uid] = [];

	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			{
			add currently_tracked_files[read_file];
			system(fmt("touch \"%s\" 2>/dev/null", str_shell_escape(read_file)));
			schedule 1msec { Exec::start_watching_file(cmd$uid, read_file) };
			}
		}

	local config_strings: table[string] of string = {
		["stdin"]       = cmd$stdin,
		["read_stderr"] = "1",
	};
	Input::add_event([$name=cmd$uid,
	                  $source=fmt("%s |", cmd$cmd),
	                  $reader=Input::READER_RAW,
	                  $fields=Exec::OneLine,
	                  $ev=Exec::line,
	                  $want_record=F,
	                  $config=config_strings]);

	return when ( cmd$uid in finished_commands )
		{
		delete finished_commands[cmd$uid];
		local result = results[cmd$uid];
		delete results[cmd$uid];
		return result;
		}
	}

event bro_done()
	{
	# We are punting here and just deleting any files that haven't been processed yet.
	for ( fname in currently_tracked_files )
		{
		system(fmt("rm \"%s\"", str_shell_escape(fname)));
		}
	}
