# @TEST-EXEC: zeek -r $TRACES/irc-dcc-send.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

event connection_established(c: connection)
	{
	print get_current_conn_bytes_threshold(c$id, T);
	print get_current_conn_bytes_threshold(c$id, F);
	print get_current_conn_packets_threshold(c$id, T);
	print get_current_conn_packets_threshold(c$id, F);

	print fmt("Threshold set for %s", cat(c$id));
	set_current_conn_bytes_threshold(c$id, 3000, T);
	set_current_conn_bytes_threshold(c$id, 2000, F);

	set_current_conn_packets_threshold(c$id, 50, F);
	set_current_conn_packets_threshold(c$id, 63, T);

	print get_current_conn_bytes_threshold(c$id, T);
	print get_current_conn_bytes_threshold(c$id, F);
	print get_current_conn_packets_threshold(c$id, T);
	print get_current_conn_packets_threshold(c$id, F);
	}

event conn_bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	print "triggered bytes", c$id, threshold, is_orig;
	}

event conn_packets_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	print "triggered packets", c$id, threshold, is_orig;
	}
