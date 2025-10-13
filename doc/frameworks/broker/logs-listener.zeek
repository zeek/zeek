@load ./testlog

redef exit_only_after_terminate = T;

event zeek_init()
	{
	Broker::subscribe("zeek/logs");
	Broker::listen("127.0.0.1");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", endpoint;
	}

event Test::log_test(rec: Test::Info)
	{
	print "got log event", rec;

	if ( rec$num == 5 )
		terminate();
	}
