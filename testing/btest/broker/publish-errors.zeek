# @TEST-DOC: Test that calling Broker::publish() with a Cluster::Event instance fails. Regression test for #4571.
#
# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek"
#
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff send/.stderr

# @TEST-START-FILE send.zeek
redef exit_only_after_terminate = T;

event my_event(i: count)
	{
	# Not supposed to be invoked!
	exit(1);
	}

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", msg;
	local evt = Cluster::make_event(my_event, 42);
	local r = Broker::publish("/test/topic", evt);
	assert ! r;  # Supposed to fail.
	exit(0);
	}
# @TEST-END-FILE


# @TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

event zeek_init()
	{
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}
# @TEST-END-FILE
