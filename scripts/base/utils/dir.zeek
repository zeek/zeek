@load base/utils/exec
@load base/frameworks/reporter
@load base/utils/paths

module Dir;

export {
	## The default interval this module checks for files in directories when
	## using the :zeek:see:`Dir::monitor` function.
	option polling_interval = 30sec;

	## Register a directory to monitor with a callback that is called
	## every time a previously unseen file is seen.  If a file is deleted
	## and seen to be gone, then the file is available for being seen again
	## in the future.
	##
	## dir: The directory to monitor for files.
	##
	## callback: Callback that gets executed with each file name
	##           that is found.  Filenames are provided with the full path.
	##
	## poll_interval: An interval at which to check for new files.
	global monitor: function(dir: string, callback: function(fname: string),
	                         poll_interval: interval &default=polling_interval);
}

event Dir::monitor_ev(dir: string, last_files: set[string],
                      callback: function(fname: string),
                      poll_interval: interval)
	{
	when [dir, last_files, callback, poll_interval] ( local result = Exec::run([$cmd=fmt("ls -1 %s/", safe_shell_quote(dir))]) )
		{
		if ( result$exit_code != 0 )
			{
			Reporter::warning(fmt("Requested monitoring of nonexistent directory (%s).", dir));
			return;
			}

		local current_files: set[string] = set();
		local files: vector of string = vector();

		if ( result?$stdout )
			files = result$stdout;

		for ( i in files )
			{
			if ( files[i] !in last_files )
				callback(build_path_compressed(dir, files[i]));
			add current_files[files[i]];
			}

		schedule poll_interval
			{
			Dir::monitor_ev(dir, current_files, callback, poll_interval)
			};
		}
	}

function monitor(dir: string, callback: function(fname: string),
                 poll_interval: interval &default=polling_interval)
	{
	event Dir::monitor_ev(dir, set(), callback, poll_interval);
	}


