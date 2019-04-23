# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out
# 
# @TEST-EXEC: cat recv/broker.log | awk '/Broker::STATUS/ { $5="XXX"; print; }' >recv/broker.filtered.log
# @TEST-EXEC: cat send/broker.log | awk '/Broker::STATUS/ { $5="XXX"; print; }' >send/broker.filtered.log
# @TEST-EXEC: btest-diff recv/broker.filtered.log
# @TEST-EXEC: btest-diff send/broker.filtered.log

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

event do_terminate()
    {
    terminate();
    }

event print_something(i: int)
    {
    print "Something sender", i;
    }

event unpeer(endpoint: Broker::EndpointInfo)
    {
    print "unpeering";
    Broker::unpeer("127.0.0.1", endpoint$network$bound_port);
    schedule 2secs { print_something(2) };
    schedule 4secs { do_terminate() };
    }

event zeek_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::auto_publish("bro/event/my_topic", print_something);
    Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    schedule 2secs { print_something(1) };
    schedule 4secs { unpeer(endpoint) };
    }


@TEST-END-FILE


@TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

event do_terminate()
    {
    terminate();
    }

event print_something(i: int)
    {
    print "Something receiver", i;
    }

event zeek_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
    schedule 10secs { do_terminate() };
    }


@TEST-END-FILE
