redef exit_only_after_terminate = T;

global value = 0;

global event_1: event(val: count);

event bye_bye()
	{
	print "received bye-bye event";
	terminate();
	}

event publish_next()
	{
    Broker::publish("benchmark/events", event_1, value);
    ++value;
	schedule 1msec { publish_next() };
	}

event zeek_init()
	{
	local broker_port = to_port(getenv("BROKER_PORT"));
	print fmt("trying to connect to port %s", broker_port);
	Broker::subscribe("benchmark/terminate");
	Broker::peer("127.0.0.1", broker_port);
	schedule 250usec { publish_next() };
	}

