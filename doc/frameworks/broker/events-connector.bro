const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "connector";
global my_event: event(msg: string, c: count);
global my_auto_event: event(msg: string, c: count);

event bro_init()
	{
	Broker::enable();
	Broker::connect("127.0.0.1", broker_port, 1sec);
	Broker::auto_event("bro/event/my_auto_event", my_auto_event);
	}

event Broker::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	print "Broker::outgoing_connection_established",
	      peer_address, peer_port, peer_name;
	Broker::send_event("bro/event/my_event", Broker::event_args(my_event, "hi", 0));
	event my_auto_event("stuff", 88);
	Broker::send_event("bro/event/my_event", Broker::event_args(my_event, "...", 1));
	event my_auto_event("more stuff", 51);
	Broker::send_event("bro/event/my_event", Broker::event_args(my_event, "bye", 2));
	}

event Broker::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}
