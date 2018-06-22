redef exit_only_after_terminate = T;

event bro_init()
	{
	Broker::listen("127.0.0.1");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", endpoint;
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost", endpoint;
	terminate();
	}
