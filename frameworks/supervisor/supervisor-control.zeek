event zeek_init()
	{
	Broker::peer("127.0.0.1", 9999/tcp, 1sec);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	Broker::publish(Supervisor::topic_prefix, Supervisor::restart_request, "", "");
	}

event Supervisor::restart_response(reqid: string, result: bool)
	{
	print fmt("got result of supervisor restart request: %s", result);
	terminate();
	}
