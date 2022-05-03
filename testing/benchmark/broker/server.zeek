redef exit_only_after_terminate = T;

global event_count = 0;

global event_1: event(val: count);

event event_1(value: count)
	{
    ++event_count;
	}

event bye_bye()
	{
	print "received bye-bye event";
	terminate();
	}

event print_stats()
	{
	print "received ", event_count, " events/s";
	event_count = 0;
	schedule 1sec { print_stats() };
	}

event zeek_init()
	{
	local broker_port = to_port(getenv("BROKER_PORT"));
	Broker::subscribe("benchmark/terminate");
	Broker::subscribe("benchmark/events");
	Broker::listen("127.0.0.1", broker_port);
	print fmt("listening on port %d", broker_port);
	schedule 1sec { print_stats() };
	}
