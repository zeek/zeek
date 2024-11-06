# @TEST-DOC: Using table() or set() for a Broker::publish() or Broker::make_event() should do the right thing.
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

@TEST-START-FILE common.zeek
type ResultTable: table[string] of count;
type ResultSet : set[count];

global ping: event(msg: string, t: ResultTable) &is_used;
global pong: event(msg: string, t: ResultTable) &is_used;

global ping_set: event(msg: string, s: ResultSet) &is_used;
global pong_set: event(msg: string, s: ResultSet) &is_used;
@TEST-END-FILE

@TEST-START-FILE send.zeek
@load ./common.zeek

redef exit_only_after_terminate = T;

global event_count = 0;


event zeek_init()
    {
    Broker::subscribe("zeek/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }

function send_events()
    {
    local e = Broker::make_event(ping, "my-message-make-event", table());
    Broker::publish("zeek/event/my_topic", e);
    Broker::publish("zeek/event/my_topic", ping, "my-message-args", table());

    local es = Broker::make_event(ping_set, "my-message-make-event", set());
    Broker::publish("zeek/event/my_topic", es);
    Broker::publish("zeek/event/my_topic", ping_set, "my-message-args", set());
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    send_events();
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    terminate();
    }

event pong(msg: string, t: ResultTable)
    {
    ++event_count;
    print "pong", msg, |t|;
    }

event pong_set(msg: string, s: ResultSet)
    {
    ++event_count;
    print "pong_set", msg, |s|;
    if ( event_count % 4 == 0 )
	send_events();
    }
@TEST-END-FILE


@TEST-START-FILE recv.zeek
@load ./common.zeek

redef exit_only_after_terminate = T;

const events_to_recv = 8;
global events_recv = 0;

event zeek_init()
	{
	Broker::subscribe("zeek/event/my_topic");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	}

event ping(msg: string, t: ResultTable)
	{
	++events_recv;
	print "ping", msg, |t|;
	Broker::publish("zeek/event/my_topic", pong, msg, t);
	}

event ping_set(msg: string, s: ResultSet)
	{
	++events_recv;
	if ( events_recv > events_to_recv )
		{
		terminate();
		return;
		}

	print "ping_set", msg, |s|;
	Broker::publish("zeek/event/my_topic", pong_set, msg, s);
	}
@TEST-END-FILE
