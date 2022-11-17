# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -D -b ../recv.zeek >recv.out 2>recv.error"
# @TEST-EXEC: btest-bg-run send "zeek -D -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.error
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

####
# NOTE: for "use-C++", this test performs differently depending on whether
# send.zeek and recv.zeek are compiled together (in which case the lambda
# still works), or separately.
####

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;
type myfunctype: function(c: count) : function(d: count) : count;

global global_with_same_name = 10;

global ping: event(msg: string, f: myfunctype);

event zeek_init()
    {
    Broker::subscribe("zeek/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }

global n = 0;

function send_event()
    {
    local event_count = 1;
    # log fails to be looked up because of a missing print statement
    # functions must have the same name on both ends of broker.
    local log : myfunctype = function(c: count) : function(d: count) : count
        {
        # print fmt("inside: %s | outside: %s | global: %s", c, event_count, global_with_same_name);
        return function[c](d: count) : count { return d + c; };
        };

        local e2 = Broker::make_event(ping, "function 1", log);
        Broker::publish("zeek/event/my_topic", e2);
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
    print fmt("sender got pong: %s", msg);
    local adder = f(n);
    print adder(76);
    send_event();
    }

@TEST-END-FILE

@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;
const events_to_recv = 1;
type myfunctype: function(c: count) : function(d: count) : count;

global global_with_same_name = 100;

global pong: event(msg: string, f: myfunctype) &is_used;

# This is one, of many, ways to declare your functions that you plan to receive.
# All you are doing is giving the parser a version of their body, so they can be
# anywhere. This seems to work quite nicely because it keeps them scoped and stops
# them from ever being evaluated.
function my_funcs()
    {
    return;

    local event_count = 11;

    local l : myfunctype = function(c: count) : function(d: count) : count
    {
    print fmt("dogs");
    return function[c](d: count) : count { return d + c; };
    };
    }

event die() { terminate(); }

event zeek_init()
    {
    Broker::subscribe("zeek/event/my_topic");
    Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
    schedule 5sec { die() };
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

event ping(msg: string, f: myfunctype) &is_used
    {
    print fmt("receiver got ping: %s", msg);
    ++n;
    local adder = f(n);
    print adder(76);

    if ( n == events_to_recv )
        terminate();
    else
        {
        local e = Broker::make_event(pong, msg, f);
        Broker::publish("zeek/event/my_topic", e);
        }
    }

@TEST-END-FILE
