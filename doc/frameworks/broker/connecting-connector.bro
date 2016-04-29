const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "connector";

event bro_init()
	{
	Broker::enable();
	Broker::connect("127.0.0.1", broker_port, 1sec);
	}

event Broker::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	print "Broker::outgoing_connection_established",
		  peer_address, peer_port, peer_name;
	terminate();
	}
