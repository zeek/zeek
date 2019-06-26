##! Turns on profiling of Zeek resource consumption.

module Profiling;

## Set the profiling output file.
redef profiling_file = open_log_file("prof");

## Set the cheap profiling interval.
redef profiling_interval = 15 secs;

## Set the expensive profiling interval (multiple of
## :zeek:id:`profiling_interval`).
redef expensive_profiling_multiple = 20;

event zeek_init()
	{
	set_buf(profiling_file, F);
	}

