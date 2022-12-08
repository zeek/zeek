# @TEST-DOC: Disabling an unrelated event group caused auto-publish to break because the remote event had no bodies and got disabled. This is a regression test it's not being done again.
#
# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.zeek

global event_count = 0;

global ping: event(msg: string, c: count);

event zeek_init()
	{
	Broker::subscribe("zeek/event/my_topic");
	Broker::auto_publish("zeek/event/my_topic", ping);
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

function send_event()
	{
	event ping("my-message", ++event_count);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("sender added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	send_event();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("sender lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	terminate();
	}

event pong(msg: string, n: count) &is_used
	{
	print fmt("sender got pong: %s, %s", msg, n);
	send_event();
	}

module TestDumpEvents;

event pong(msg: string, n: count) &is_used
	{
	print fmt("ERROR: This should not be visible: %s, %s", msg, n);
	}

event zeek_init()
	{
	disable_module_events("TestDumpEvents");
	}

@TEST-END-FILE


@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

const events_to_recv = 5;

global pong: event(msg: string, c: count);

event zeek_init()
	{
	Broker::subscribe("zeek/event/my_topic");
	Broker::auto_publish("zeek/event/my_topic", pong);
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("receiver added peer: endpoint=%s msg=%s",
	endpoint$network$address, msg);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("receiver lost peer: endpoint=%s msg=%s",
	endpoint$network$address, msg);
	}

event ping(msg: string, n: count) &is_used
	{
	print fmt("receiver got ping: %s, %s", msg, n);

	if ( n == events_to_recv )
		{
		terminate();
		return;
		}

	event pong(msg, n);
	}

module TestDumpEvents;

event ping(msg: string, n: count) &is_used
	{
	print fmt("ERROR: This should not be visible: %s, %s", msg, n);
	}

event zeek_init()
	{
	disable_module_events("TestDumpEvents");
	}

@TEST-END-FILE
