# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek test_var=newval >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out

@TEST-START-FILE send.zeek

const test_var = "init" &redef;

event zeek_init()
	{
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	Broker::publish_id("zeek/ids/test", "test_var");
	}

@TEST-END-FILE

@TEST-START-FILE recv.zeek

const test_var = "init" &redef;

event check_var()
	{
	if ( test_var == "init" )
		schedule 0.1sec { check_var() };
	else
		{
		print "updated val", test_var;
		terminate();
		}
	}

event zeek_init()
	{
	print "initial val", test_var;
	Broker::subscribe("zeek/ids");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	schedule 1sec { check_var() };
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	terminate();
	}

@TEST-END-FILE
