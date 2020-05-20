
## Given an interval, returns a string representing the minutes and seconds
## in the interval (for example, "3m34s").
function duration_to_mins_secs(dur: interval): string
	{
	local dur_count = double_to_count(interval_to_double(dur));
	return fmt("%dm%ds", dur_count/60, dur_count%60);
	}
