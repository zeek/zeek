event zeek_init()
	{
	# Setup some variables. This uses current_time() since time constants don't
	# exist in Zeek.
	local time_spotted: time = current_time();
	# You can add an interval to a time to get another time
	local time_spotted2 = time_spotted + 1sec;
	# You can also subtract two times for an interval
	local interval_between = time_spotted2 - time_spotted;
	# You can add two intervals together
	interval_between += current_time() - time_spotted;

	print fmt("Time between events: %s", interval_between);

	# Intervals can be used for concepts such as timeouts or for analyzing
	# bursts of traffic.
	local timeout_interval = 1sec;
	if ( interval_between > timeout_interval )
		print "Interval was timed out";
	else
		print "Interval was within the timeout";
	}
