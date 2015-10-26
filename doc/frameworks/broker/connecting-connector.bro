const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef BrokerComm::endpoint_name = "connector";

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::connect("127.0.0.1", broker_port, 1sec);
	}

event BrokerComm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	print "BrokerComm::outgoing_connection_established",
		  peer_address, peer_port, peer_name;
	terminate();
	}
