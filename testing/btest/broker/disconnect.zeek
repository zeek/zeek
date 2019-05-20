# @TEST-PORT: BROKER_PORT

# @TEST-EXEC: btest-bg-run recv "zeek -B broker -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -B broker -b ../send.zeek >send.out"

# @TEST-EXEC: $SCRIPTS/wait-for-pid $(cat recv/.pid) 45 || (btest-bg-wait -k 1 && false)

# @TEST-EXEC: btest-bg-run recv2 "zeek -B broker -b ../recv.zeek >recv2.out"
# @TEST-EXEC: btest-bg-wait 45

# @TEST-EXEC: btest-diff send/send.out
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff recv2/recv2.out

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

global peers = 0;
const test_topic = "bro/test/my_topic";

event my_event(i: count)
	{
	print "sender got event", i;
	}

event zeek_init()
	{
	Broker::subscribe(test_topic);
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer lost", msg;

	if ( peers == 2 )
		terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	++peers;
	print "peer added", msg;
	Broker::publish(test_topic, my_event, peers);
	}

@TEST-END-FILE


@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

const test_topic = "bro/test/my_topic";

event my_event(i: count)
	{
	print "receiver got event", i;
	terminate();
	}

event zeek_init()
	{
	Broker::subscribe(test_topic);
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "peer added", msg;
	}

@TEST-END-FILE
