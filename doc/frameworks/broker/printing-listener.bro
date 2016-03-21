const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef BrokerComm::endpoint_name = "listener";
global msg_count = 0;

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_prints("bro/print/");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established", peer_name;
	}

event BrokerComm::print_handler(msg: string)
	{
	++msg_count;
	print "got print message", msg;

	if ( msg_count == 3 )
		terminate();
	}
