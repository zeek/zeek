# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run recv "bro -B broker -b ../recv.bro >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -B broker -b ../send.bro >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.bro

redef exit_only_after_terminate = T;

global event_count = 0;

global ping: event(msg: string, c: count);

event bro_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::peer("127.0.0.1");
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

event pong(msg: string, n: count)
    {
    print "is_remote should be T, and is", is_remote_event();
    print fmt("sender got pong: %s, %s", msg, n);
    send_event();
    }

@TEST-END-FILE


@TEST-START-FILE recv.bro

redef exit_only_after_terminate = T;

const events_to_recv = 5;

global handler: event(msg: string, c: count);
global auto_handler: event(msg: string, c: count);

global pong: event(msg: string, c: count);

event bro_init()
        {
        Broker::subscribe("bro/event/my_topic");
        Broker::listen("127.0.0.1");
        }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
        {
        print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
        }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
        {
        print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
        }

event ping(msg: string, n: count)
        {
	print "is_remote should be T, and is", is_remote_event();
        print fmt("receiver got ping: %s, %s", msg, n);

        if ( n == events_to_recv )
                {
		print get_broker_stats();
                terminate();
                return;
                }

        local e = Broker::make_event(pong, msg, n);
        Broker::publish("bro/event/my_topic", e);
        }

@TEST-END-FILE
