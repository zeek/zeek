# @TEST-DOC: Test get_current_packet_ts() in comparison with network_time().
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT > output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

event network_time_init()
	{
	print fmt("network_time_init network time: %s", network_time());
	print fmt("network_time_init packet ts:    %s", get_current_packet_ts());
	}

# Note: Gracefully closed connections will be actually removed after
# tcp_close_delay (default 5 secs).
event connection_state_remove(c: connection)
	{
	print fmt("conn_state_remove network time: %s", network_time());
	print fmt("conn_state_remove packet ts:    %s", get_current_packet_ts());
	}
