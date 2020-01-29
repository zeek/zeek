event zeek_init()
	{
	Broker::peer("127.0.0.1", 9999/tcp, 1sec);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	Broker::publish(SupervisorControl::topic_prefix, SupervisorControl::restart_request, "", "");
	}

event SupervisorControl::restart_response(reqid: string, result: bool)
	{
	print fmt("got result of supervisor restart request: %s", result);
	terminate();
	}
