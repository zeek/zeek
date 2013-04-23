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
	when ( local result = Exec::run([$cmd=fmt("ls -i \"%s/\"", str_shell_escape(dir))]) )
		{
		if ( result$exit_code != 0 )
			{
			Reporter::warning(fmt("Requested monitoring of non-existent directory (%s).", dir));
			return;
			}

		local current_files: set[string] = set();
		local files = result$stdout;
		for ( i in files )
			{
			local parts = split1(files[i], / /);
			if ( parts[1] !in last_files )
				callback(build_path_compressed(dir, parts[2]));
			add current_files[parts[1]];
			}
		schedule polling_interval { Dir::monitor_ev(dir, current_files, callback) };
		}
	}

function monitor(dir: string, callback: function(fname: string))
	{
	event Dir::monitor_ev(dir, set(), callback);
	}


