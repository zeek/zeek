# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-send.trace %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr
#
# This tests that no events are raised once all thresholds have been deleted.

@load base/protocols/conn

event connection_established(c: connection)
	{
	ConnThreshold::set_bytes_threshold(c, 1, T);
	ConnThreshold::delete_bytes_threshold(c, 1, T);
	ConnThreshold::set_duration_threshold(c, 0.1secs);
	ConnThreshold::delete_duration_threshold(c, 0.1secs);
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

event ConnThreshold::duration_threshold_crossed(c: connection, threshold: interval, is_orig: bool)
	{
	print "triggered duration", c$id, threshold, is_orig;
	}
