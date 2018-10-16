# @TEST-SERIALIZE: comm

# @TEST-EXEC: btest-bg-run recv "bro -B broker -b ../recv.bro >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -B broker -b ../send.bro >send.out"

# @TEST-EXEC: $SCRIPTS/wait-for-pid $(cat recv/.pid) 45 || (btest-bg-wait -k 1 && false)

# @TEST-EXEC: btest-bg-run recv2 "bro -B broker -b ../recv.bro >recv2.out"
# @TEST-EXEC: btest-bg-wait 45

# @TEST-EXEC: btest-diff send/send.out
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff recv2/recv2.out

@TEST-START-FILE send.bro

redef exit_only_after_terminate = T;

global peers = 0;
const test_topic = "bro/test/my_topic";

event my_event(i: count)
	{
	print "sender got event", i;
	}

event bro_init()
	{
	Broker::subscribe(test_topic);
	Broker::peer("127.0.0.1");
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


@TEST-START-FILE recv.bro

redef exit_only_after_terminate = T;

const test_topic = "bro/test/my_topic";

event my_event(i: count)
	{
	print "receiver got event", i;
	terminate();
	}

event bro_init()
	{
	Broker::subscribe(test_topic);
	Broker::listen("127.0.0.1");
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
