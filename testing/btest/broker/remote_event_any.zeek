# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -B broker -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -B broker -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

global event_count = 0;

global ping: event(msg: string, c: any);

event zeek_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    print "is_remote should be F, and is", is_remote_event();
    }

function send_event()
    {
    ++event_count;
    local e = Broker::make_event(ping, "my-message", event_count);
    Broker::publish("bro/event/my_topic", e);
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender added peer: endpoint=%s msg=%s",
    endpoint$network$address, msg);
    send_event();
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender lost peer: endpoint=%s msg=%s",
    endpoint$network$address, msg);
    terminate();
    }

event pong(msg: string, n: any)
    {
    print "is_remote should be T, and is", is_remote_event();

    if ( n is count )
        print fmt("sender got pong: %s, %s", msg, n as count);

    send_event();
    }

@TEST-END-FILE


@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

const events_to_recv = 5;

global handler: event(msg: string, c: count);
global auto_handler: event(msg: string, c: count);

global pong: event(msg: string, c: any);

event zeek_init()
        {
        Broker::subscribe("bro/event/my_topic");
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

event ping(msg: string, n: any)
        {
        print "is_remote should be T, and is", is_remote_event();

        if ( n is count )
        	print fmt("receiver got ping: %s, %s", msg, n as count);

        if ( (n as count) == events_to_recv )
                {
		print get_broker_stats();
                terminate();
                return;
                }

		if ( (n as count) % 2 == 0 )
			Broker::publish("bro/event/my_topic", pong, msg, n as count);
		else
			# internals should not wrap n into another Broker::Data record
			Broker::publish("bro/event/my_topic", pong, msg, n);
        }

@TEST-END-FILE
