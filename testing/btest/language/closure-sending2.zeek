# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -D -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -D -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;
type myfunctype: function(c: count) : function(d: count) : count;

global global_with_same_name = 10;

global ping: event(msg: string, f: myfunctype);

event zeek_init()
    {
    print "hello :)";
    Broker::subscribe("zeek/event/my_topic");
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }

global n = 0;

function send_event()
    {
    # in this frame event_count has an offset of three.
    # in the receiving frame it has an offset of one.
    # this tests to ensure that id lookups are being routed properly.
    local dog = 0;
    local not_dog = 1;
    local event_count = 11;

    local log : myfunctype = function[event_count](c: count) : function(d: count) : count
        {
        print fmt("inside: %s | outside: %s | global: %s", c, event_count, global_with_same_name);
        return function[c](d: count) : count { return d + c; };
        };

	local two_part_adder_maker = function (begin : count) : function (base_step : count) : function ( step : count) : count
		{
		return function [begin](base_step : count) : function (step : count) : count
			{
                print fmt("begin: %s | base_step: %s", begin, base_step);
				return function[begin, base_step] (step : count) : count
					{
                    print fmt("begin: %s | base_step: %s | step: %s", begin, base_step, step);
					return (begin += base_step + step); }; }; };
	
	local l = two_part_adder_maker(100);
	local stepper = l(50);

    ++n;
    ++event_count;
    if ( n % 2 == 0)
        {
        local e2 = Broker::make_event(ping, "function 1", l);
        Broker::publish("zeek/event/my_topic", e2);
        }
    else
        {
        local e = Broker::make_event(ping, "function 2", log);
        Broker::publish("zeek/event/my_topic", e);
        }
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
const events_to_recv = 7;
type myfunctype: function(c: count) : function(d: count) : count;
# type myfunctype: function(c: count);

global global_with_same_name = 100;

global pong: event(msg: string, f: myfunctype);

# This is one, of many, ways to declare your functions that you plan to receive.
# All you are doing is giving the parser a version of their body, so they can be
# anywhere. This seems to work quite nicely because it keeps them scoped and stops
# them from ever being evaluated.
function my_funcs()
    {
    return;

    local begin = 100;
    local event_count = begin;

    local l : myfunctype = function[event_count](c: count) : function(d: count) : count
    {
    print fmt("inside: %s | outside: %s | global: %s", c, event_count, global_with_same_name);
    return function[c](d: count) : count { return d + c; };
    };

    local dog_fish = function [begin](base_step : count) : function (step : count) : count
        {
# actual formatting doesn't matter for name resolution.
print fmt("begin: %s | base_step: %s", begin, base_step);
        return function [begin, base_step](step : count) : count
            {
                        print fmt("begin: %s | base_step: %s | step: %s", begin, base_step, step);
                        return (begin += base_step + step); }; };
        }

event zeek_init()
    {
    print "hello :-)";
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
    print fmt("receiver got ping: %s", msg);
    ++n;
    local adder = f(n);
    print adder(76);

    if ( n == events_to_recv )
        {
        terminate();
        }
    else
        {
        local e = Broker::make_event(pong, msg, f);
        Broker::publish("zeek/event/my_topic", e);
        }
    }

@TEST-END-FILE
