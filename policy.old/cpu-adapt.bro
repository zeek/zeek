# $Id: cpu-adapt.bro 1904 2005-12-14 03:27:15Z vern $
#
# Adjust load level based on cpu load.

@load load-level

# We increase the load-level if the average CPU load (percentage) is
# above this limit.
global cpu_upper_limit = 70.0 &redef;

# We derease the load-level if the average CPU load is below this limit.
global cpu_lower_limit = 30.0 &redef;

# Time interval over which we average the CPU load.
global cpu_interval = 1 min &redef;

global cpu_last_proc_time = 0 secs;
global cpu_last_wall_time: time = 0;

event cpu_measure_load()
	{
	local res = resource_usage();
	local proc_time = res$user_time + res$system_time;
	local wall_time = current_time();

	if ( cpu_last_proc_time > 0 secs )
		{
		local dproc = proc_time - cpu_last_proc_time;
		local dwall = wall_time - cpu_last_wall_time;
		local load = dproc / dwall * 100.0;

		print ll_file, fmt("%.6f CPU load %.02f", network_time(), load);

		# Second test is for whether we have any room to change
		# things.  It shouldn't be hardwired to "xxx10" ....
		if ( load > cpu_upper_limit &&
		     current_load_level != LoadLevel10 )
			{
			print ll_file, fmt("%.6f CPU load above limit: %.02f",
						network_time(), load);
			increase_load_level();
			}

		else if ( load < cpu_lower_limit &&
			  current_load_level != LoadLevel1 )
			{
			print ll_file, fmt("%.6f CPU load below limit: %.02f",
						network_time(), load);
			decrease_load_level();
			}
		}

	cpu_last_proc_time = proc_time;
	cpu_last_wall_time = wall_time;

	schedule cpu_interval { cpu_measure_load() };
	}

event bro_init()
	{
	schedule cpu_interval { cpu_measure_load() };
	}
