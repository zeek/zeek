const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "listener";

event bro_init()
	{
	Broker::enable();
	Broker::listen(broker_port, "127.0.0.1");
	}

event Broker::incoming_connection_established(peer_name: string)
	{
	print "Broker::incoming_connection_established", peer_name;
	}

event Broker::incoming_connection_broken(peer_name: string)
	{
	print "Broker::incoming_connection_broken", peer_name;
	terminate();
	}
