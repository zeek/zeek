##! Time-related functions.

## Given an interval, returns a string representing the minutes and seconds
## in the interval (for example, "3m34s").
function duration_to_mins_secs(dur: interval): string
	{
	local dur_count = double_to_count(interval_to_double(dur));
	return fmt("%dm%ds", dur_count/60, dur_count%60);
	}

## Time value representing the 0 timestamp.
const null_ts = double_to_time(0);

## Calculate the packet lag, i.e. the difference between wall clock and the
## timestamp of the currently processed packet. If Zeek is not processing a
## packet, the function returns a 0 interval value.
function get_packet_lag(): interval
	{
	# We use get_current_packet_ts() instead of network_time() here, because
	# network time does not immediately fall back to wall clock if there is
	# no packet. Instead, network time remains set to the last seen packet's
	# timestamp for ``packet_source_inactivity_timeout``.
	local pkt_ts = get_current_packet_ts();
	if (pkt_ts == null_ts)
		return 0 sec;

	return current_time() - pkt_ts;
	}
