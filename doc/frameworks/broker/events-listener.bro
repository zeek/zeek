const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef BrokerComm::endpoint_name = "listener";
global msg_count = 0;
global my_event: event(msg: string, c: count);
global my_auto_event: event(msg: string, c: count);

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_events("bro/event/");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established", peer_name;
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
