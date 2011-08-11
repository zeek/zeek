##! Turns on profiling of Bro resource consumption.

module Profiling;

redef profiling_file = open_log_file("prof");

export {
	## Cheap profiling every 15 seconds.
	redef profiling_interval = 15 secs &redef;
}

# Expensive profiling every 5 minutes.
redef expensive_profiling_multiple = 20;

event bro_init()
	{
	set_buf(profiling_file, F);
	}

