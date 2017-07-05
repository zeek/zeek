# @TEST-SERIALIZE: brokercomm
#
# @TEST-EXEC: btest-bg-run recv "bro -B main-loop,broker -b ../recv.bro >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -B main-loop,broker -b ../send.bro >send.out"
# @TEST-EXEC: 
# @TEST-EXEC: sleep 3 && kill $(cat recv/.pid) && sleep 1 && rm -rf recv
# @TEST-EXEC: btest-bg-run recv "bro -B broker -b ../recv.bro >recv.out"
#
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out
# 
# @TEST-EXEC: cat recv/broker.log | awk '/Broker::STATUS/ { $5="XXX"; print; }' >recv/broker.filtered.log
# @TEST-EXEC: cat send/broker.log | awk '/Broker::STATUS/ { $5="XXX"; print; }' >send/broker.filtered.log
# @TEST-EXEC: btest-diff recv/broker.filtered.log
# @TEST-EXEC: btest-diff send/broker.filtered.log

@TEST-START-FILE send.bro

redef Broker::default_connect_retry=1secs;
redef Broker::default_listen_retry=1secs;
redef exit_only_after_terminate = T;

event do_terminate()
    {
    terminate();
    }

event print_something(i: int)
    {
    print "Something sender", i;
    }

event bro_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::auto_publish("bro/event/my_topic", print_something);
    Broker::auto_publish("bro/event/my_topic", do_terminate);
    Broker::peer("127.0.0.1");

    schedule 3secs { print_something(1) };
    schedule 7secs { print_something(2) };
    schedule 10secs { do_terminate() };
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    }


@TEST-END-FILE


@TEST-START-FILE recv.bro

redef Broker::default_connect_retry=1secs;
redef Broker::default_listen_retry=1secs;
redef exit_only_after_terminate = T;

event do_terminate()
    {
    terminate();
    }

event print_something(i: int)
    {
    print "Something receiver", i;
    }

event bro_init()
    {
    Broker::subscribe("bro/event/my_topic");
    Broker::listen("127.0.0.1");
    }


@TEST-END-FILE
