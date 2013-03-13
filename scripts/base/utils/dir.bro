@load base/utils/exec
@load base/frameworks/reporter
@load base/utils/paths

module Dir;

export {
	## Register a directory to monitor with a callback that is called 
	## every time a previously unseen file is seen.  If a file is deleted
	## and seen to be gone, the file is available for being seen again in 
	## the future.
	##
	## dir: The directory to monitor for files.
	##
	## callback: Callback that gets executed with each file name 
	##           that is found.  Filenames are provided with the full path.
	global monitor: function(dir: string, callback: function(fname: string));

	## The interval this module checks for files in directories when using 
	## the :bro:see:`Dir::monitor` function.
	const polling_interval = 30sec &redef;
}

event Dir::monitor_ev(dir: string, last_files: set[string], callback: function(fname: string))
	{
	when ( local result = Exec::run([$cmd=fmt("ls \"%s\"", str_shell_escape(dir))]) )
		{
		if ( result$exit_code != 0 )
			{
			Reporter::warning("Requested monitoring of non-existent directory.");
			return;
			}

		local current_files: set[string] = set();
		local files = result$stdout;
		for ( i in files )
			{
			if ( files[i] !in last_files )
				callback(build_path_compressed(dir, files[i]));
			add current_files[files[i]];
			}
		schedule polling_interval { Dir::monitor_ev(dir, current_files, callback) };
		}
	}

function monitor(dir: string, callback: function(fname: string))
	{
	event Dir::monitor_ev(dir, set(), callback);
	}


