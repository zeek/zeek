
## Given an interval, returns a string of the form 3m34s to
## give a minimalized human readable string for the minutes 
## and seconds represented by the interval.
function duration_to_mins_secs(dur: interval): string
	{
	local dur_count = double_to_count(interval_to_double(dur));
	return fmt("%dm%ds", dur_count/60, dur_count%60);
	}
