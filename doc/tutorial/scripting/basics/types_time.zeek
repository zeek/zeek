event zeek_init()
	{
	# Setup some variables. This uses current_time() since time constants don't
	# exist in Zeek.
	local time_spotted: time = current_time();
	sleep(1sec); # Waits for a second to put time between two current_time calls
	local time_spotted2: time = current_time();

	# You can add or subtract times from each other to get an interval
	local interval_between: interval = time_spotted2 - time_spotted;
	print fmt("Time between events: %s", time_spotted2 - time_spotted);

	# Intervals can be used for concepts such as timeouts or for analyzing
	# bursts of traffic.
	local timeout_interval = 1sec;
	if ( interval_between > timeout_interval )
		print "Interval was timed out";
	else
		print "Interval was within the timeout";
	}
