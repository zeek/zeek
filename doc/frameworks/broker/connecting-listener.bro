const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef BrokerComm::endpoint_name = "listener";

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established", peer_name;
	}

event BrokerComm::incoming_connection_broken(peer_name: string)
	{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
	}
