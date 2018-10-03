# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run recv "bro -B broker -b ../recv.bro >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -B broker -b ../send.bro test_var=newval >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out

@TEST-START-FILE send.bro

const test_var = "init" &redef;

event bro_init()
	{
	Broker::peer("127.0.0.1");
	}

event die()
	{
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	Broker::publish_id("bro/ids/test", "test_var");
	schedule 1sec { die() };
	}

@TEST-END-FILE

@TEST-START-FILE recv.bro

const test_var = "init" &redef;

event bro_init()
	{
	print "intial val", test_var;
	Broker::subscribe("bro/ids");
	Broker::listen();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added";
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost";
	print "updated val", test_var;
	terminate();
	}

@TEST-END-FILE
