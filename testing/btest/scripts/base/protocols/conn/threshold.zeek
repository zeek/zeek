# @TEST-EXEC: zeek -r $TRACES/irc-dcc-send.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

event connection_established(c: connection)
	{
	print fmt("Threshold set for %s", cat(c$id));
	ConnThreshold::set_bytes_threshold(c, 1, T);
	ConnThreshold::set_bytes_threshold(c, 2500, T);
	ConnThreshold::set_bytes_threshold(c, 2700, T);
	ConnThreshold::set_bytes_threshold(c, 3000, T);
	ConnThreshold::delete_bytes_threshold(c, 3000, T);
	ConnThreshold::set_bytes_threshold(c, 2000, F);

	ConnThreshold::set_packets_threshold(c, 50, F);
	ConnThreshold::set_packets_threshold(c, 51, F);
	ConnThreshold::set_packets_threshold(c, 52, F);
	ConnThreshold::delete_packets_threshold(c, 51, F);
	ConnThreshold::set_packets_threshold(c, 63, T);
	ConnThreshold::delete_packets_threshold(c, 63, T);
	}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	print "triggered bytes", c$id, threshold, is_orig;
	}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	print "triggered packets", c$id, threshold, is_orig;
	}
