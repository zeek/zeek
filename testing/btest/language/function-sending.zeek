# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "ZEEK_COMPILE_ALL=1 zeek -D -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -D -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;
global event_count = 0;
type myfunctype: function(c: count);
function myfunc(c: count)
    {
    print fmt("bodiesdontsend(%s)", c);
    }
global ping: event(msg: string, f: myfunctype);
event zeek_init()
    {
    Broker::subscribe("zeek/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }
function send_event()
    {
    ++event_count;
    local e = Broker::make_event(ping, "my-message", myfunc);
    Broker::publish("zeek/event/my_topic", e);
    }
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer added";
    send_event();
    }
event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer lost";
    terminate();
    }
event pong(msg: string, f: myfunctype)
    {
    print fmt("sender got pong: %s, %s", msg, f);
    f(event_count);
    send_event();
    }

@TEST-END-FILE

@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;
const events_to_recv = 5;
type myfunctype: function(c: count);
function myfunc(c: count)
    {
    print fmt("myfunc(%s)", c);
    }
global pong: event(msg: string, f: myfunctype);
event zeek_init()
    {
    Broker::subscribe("zeek/event/my_topic");
    Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer added";
    }
event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer lost";
    }
global n = 0;
event ping(msg: string, f: myfunctype)
    {
    print fmt("receiver got ping: %s, %s", msg, f);
    ++n;
    f(n);
    if ( n == events_to_recv )
        terminate();
    else
        {
        local e = Broker::make_event(pong, msg, f);
        Broker::publish("zeek/event/my_topic", e);
        }
    }

@TEST-END-FILE
