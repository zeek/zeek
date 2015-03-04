
const broker_port: port &redef;
redef exit_only_after_terminate = T;
redef Comm::endpoint_name = "listener";

event bro_init()
	{
	Comm::enable();
	Comm::listen(broker_port, "127.0.0.1");
	}

event Comm::incoming_connection_established(peer_name: string)
	{
	print "Comm::incoming_connection_established", peer_name;
	}

event Comm::incoming_connection_broken(peer_name: string)
	{
	print "Comm::incoming_connection_broken", peer_name;
	terminate();
	}
