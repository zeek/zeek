# @TEST-EXEC: zeek -B main-loop,broker -b send.zeek >send.out
# @TEST-EXEC: btest-diff send.out
# 

@TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

event do_terminate()
    {
    terminate();
    }

event do_something()
    {
    # Will fail and generate an error.
    Broker::unpeer("1.2.3.4", 1947/tcp);
    }

event Broker::status(endpoint: Broker::EndpointInfo, msg: string)
    {
    print "status", endpoint, endpoint$network, msg;
    }

event Broker::error(code: Broker::ErrorCode, msg: string)
    {
    print "error", code, msg;
    }

event zeek_init()
    {
    Broker::subscribe("bro/event/my_topic");
    
    schedule 2secs { do_something() };
    schedule 4secs { do_terminate() };
    }


@TEST-END-FILE

