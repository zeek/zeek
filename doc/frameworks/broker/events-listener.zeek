redef exit_only_after_terminate = T;
global msg_count = 0;
global my_event: event(msg: string, c: count);
global my_auto_event: event(msg: string, c: count);

event zeek_init()
	{
	Broker::subscribe("zeek/event/");
	Broker::listen("127.0.0.1");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", endpoint;
	}

event my_event(msg: string, c: count)
	{
	++msg_count;
	print "got my_event", msg, c;

	if ( msg_count == 5 )
		terminate();
	}

event my_auto_event(msg: string, c: count)
	{
	++msg_count;
	print "got my_auto_event", msg, c;

	if ( msg_count == 5 )
		terminate();
	}
