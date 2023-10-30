# @TEST-DOC: A connection flip does not reset the ConnVal. Regression test for #3028.

# @TEST-EXEC: zeek -b -r $TRACES/tcp/handshake-reorder.trace %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

redef record conn_id += {
	extra_id: count &optional;
};

redef record connection += {
	my_timestamp: time &optional;
};

event new_connection(c: connection)
	{
	c$id$extra_id = 42;
	c$my_timestamp = network_time();
	print network_time(), "new_connection", c$id, c$history, c$my_timestamp;
	}

event connection_flipped(c: connection)
	{
	print network_time(), "connection_flipped", c$id, c$history, c$my_timestamp;
	}

event connection_state_remove(c: connection)
	{
	print network_time(), "connection_state_remove", c$id, c$history, c$my_timestamp;
	}
