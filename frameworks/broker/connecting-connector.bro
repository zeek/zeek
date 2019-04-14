redef exit_only_after_terminate = T;

event zeek_init()
	{
	Broker::peer("127.0.0.1");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", endpoint;
	terminate();
	}
