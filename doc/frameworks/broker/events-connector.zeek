redef exit_only_after_terminate = T;
global my_event: event(msg: string, c: count);
global my_auto_event: event(msg: string, c: count);

event zeek_init()
	{
	Broker::peer("127.0.0.1");
	Broker::auto_publish("zeek/event/my_auto_event", my_auto_event);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", endpoint;
	Broker::publish("zeek/event/my_event", my_event, "hi", 0);
	event my_auto_event("stuff", 88);
	Broker::publish("zeek/event/my_event", my_event, "...", 1);
	event my_auto_event("more stuff", 51);
	local e = Broker::make_event(my_event, "bye", 2);
	Broker::publish("zeek/event/my_event", e);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event my_event(msg: string, c: count)
	{
	print "got my_event", msg, c;
	}

event my_auto_event(msg: string, c: count)
	{
	print "got my_auto_event", msg, c;
	}
