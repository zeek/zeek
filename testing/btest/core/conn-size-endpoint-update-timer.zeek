# @TEST-DOC: Ensure that a connection's orig and resp records have up-to-date data when accessing the connection within a timer event.
#
# @TEST-EXEC: zeek -b -r $TRACES/dns/long-connection.pcap %INPUT >> out
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

@load base/protocols/conn

redef udp_inactivity_timeout = 30min;

event print_connection(c: connection)
	{
	print network_time(), "print_connection", c$uid, "orig num_pkts", c$orig$num_pkts, "resp num_pkts", c$resp$num_pkts, "pkts_recvd", get_net_stats()$pkts_recvd;

	if ( connection_exists(c$id) )
		schedule 10sec { print_connection(c) };
	}

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;

	event print_connection(c);
	}

event connection_state_remove(c: connection)
	{
	print network_time(), "connection_state_remove", c$uid;

	# Print it once more!
	event print_connection(c);
	}
