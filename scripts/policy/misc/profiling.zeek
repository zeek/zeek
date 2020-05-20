##! Turns on profiling of Zeek resource consumption.

module Profiling;

function log_suffix(): string
	{
	local rval = getenv("ZEEK_LOG_SUFFIX");

	if ( rval == "" )
		return "log";

	return rval;
	}

## Set the profiling output file.
redef profiling_file = open(fmt("prof.%s", Profiling::log_suffix()));

## Set the cheap profiling interval.
redef profiling_interval = 15 secs;

## Set the expensive profiling interval (multiple of
## :zeek:id:`profiling_interval`).
redef expensive_profiling_multiple = 20;

event zeek_init()
	{
	set_buf(profiling_file, F);
	}

