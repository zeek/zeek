# $Id: profiling.bro 1102 2005-03-17 09:17:46Z vern $
#
# Turns on profiling of Bro resource consumption.

redef profiling_file = open_log_file("prof");

# Cheap profiling every 15 seconds.
redef profiling_interval = 15 secs &redef;

# Expensive profiling every 5 minutes.
redef expensive_profiling_multiple = 20;

event bro_init()
	{
	set_buf(profiling_file, F);
	}

