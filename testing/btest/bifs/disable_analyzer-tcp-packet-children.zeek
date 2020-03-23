# @TEST-EXEC: zeek -b -r $TRACES/http/pipelined-requests.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http

event connection_established(c: connection)
	{
	set_current_conn_packets_threshold(c$id, 1, T);
	}

event conn_packets_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	print "triggered packets", c$id, threshold, is_orig;
	set_current_conn_packets_threshold(c$id, threshold + 1, T);
	print disable_analyzer(c$id, current_analyzer(), T);
	}
