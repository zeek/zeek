@load ./testlog

redef exit_only_after_terminate = T;
global n = 0;

event zeek_init()
	{
	Broker::peer("127.0.0.1");
	}

event do_write()
	{
	if ( n == 6 )
		return;

	Log::write(Test::LOG, [$msg = "ping", $num = n]);
	++n;
	event do_write();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", endpoint;
	event do_write();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event Test::log_test(rec: Test::Info)
	{
	print "wrote log", rec;
	Broker::publish("zeek/logs/forward/test", Test::log_test, rec);
	}
