# @TEST-SERIALIZE: brokercomm
#
# @TEST-EXEC: btest-bg-run recv "bro -B broker -b ../recv.bro >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -B broker -b ../send.bro >send.out"
# @TEST-EXEC:
# @TEST-EXEC: sleep 6 && kill $(cat recv/.pid) && sleep 1 && echo 0 >recv/.exitcode
# @TEST-EXEC: btest-bg-run recv2 "bro -B broker -b ../recv.bro >recv2.out"
#
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff send/send.out
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff recv2/recv2.out
#
# @TEST-EXEC: cat send/broker.log | awk '/Broker::STATUS/ { $5="XXX"; print; }' >send/broker.filtered.log
# @TEST-EXEC: cat recv/broker.log | awk '/Broker::STATUS/ { $5="XXX"; print; }' >recv/broker.filtered.log
# @TEST-EXEC: cat recv2/broker.log | grep -v "lost remote peer" | awk '/Broker::STATUS/ { $5="XXX"; print; }' >recv2/broker.filtered.log
# @TEST-EXEC: btest-diff send/broker.filtered.log
# @TEST-EXEC: btest-diff recv/broker.filtered.log
# @TEST-EXEC: btest-diff recv2/broker.filtered.log

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

    schedule 4secs { print_something(1) };
    schedule 10secs { print_something(2) };
    schedule 15secs { do_terminate() };
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer lost", msg;
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer added", msg;
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

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    # In the 2nd run, this may be lost at termination, so don't output.
    #print "peer lost", msg;
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "peer added", msg;
    }

@TEST-END-FILE
