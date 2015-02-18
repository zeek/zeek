const broker_port: port &redef;
redef exit_only_after_terminate = T;
redef Comm::endpoint_name = "connector";
global my_event: event(msg: string, c: count);
global my_auto_event: event(msg: string, c: count);

event bro_init()
	{
	Comm::enable();
	Comm::connect("127.0.0.1", broker_port, 1sec);
	Comm::auto_event("bro/event/my_auto_event", my_auto_event);
	}

event Comm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	print "Comm::outgoing_connection_established",
	      peer_address, peer_port, peer_name;
	Comm::event("bro/event/my_event", Comm::event_args(my_event, "hi", 0));
	event my_auto_event("stuff", 88);
	Comm::event("bro/event/my_event", Comm::event_args(my_event, "...", 1));
	event my_auto_event("more stuff", 51);
	Comm::event("bro/event/my_event", Comm::event_args(my_event, "bye", 2));
	}

event Comm::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}
