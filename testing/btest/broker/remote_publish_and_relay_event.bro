# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run three "bro -B broker -b ../three.bro >three.out"
# @TEST-EXEC: btest-bg-run two "bro -B broker -b ../two.bro >two.out"
# @TEST-EXEC: btest-bg-run one "bro -B broker -b ../one.bro >one.out"
#
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff one/one.out
# @TEST-EXEC: btest-diff two/two.out
# @TEST-EXEC: btest-diff three/three.out

@TEST-START-FILE one.bro

redef exit_only_after_terminate = T;

event my_event(s: string)
	{
	print "got my_event", s;
	}

event ready_event()
	{
	print "got ready event";

	Broker::publish_and_relay("bro/event/pre-relay", "bro/event/post-relay",
	                          my_event, "hello world");
	}

event bro_init()
    {
    Broker::subscribe("bro/event/ready");
    Broker::peer("127.0.0.1", 10000/tcp);
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender added peer: endpoint=%s msg=%s",
    		  endpoint$network$address, msg);
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("sender lost peer: endpoint=%s msg=%s",
    		  endpoint$network$address, msg);
    terminate();
    }

@TEST-END-FILE


@TEST-START-FILE two.bro

redef exit_only_after_terminate = T;

global peers_added = 0;

event my_event(s: string)
	{
	print "got my_event", s;
	}

event ready_event()
	{
	}

event bro_init()
    {
    Broker::subscribe("bro/event/pre-relay");
    Broker::listen("127.0.0.1", 10000/tcp);
	Broker::peer("127.0.0.1", 9999/tcp);
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    ++peers_added;

    if ( peers_added == 2 )
    	{
		print "sending ready event";
        Broker::publish("bro/event/ready", ready_event);
    	}
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    terminate();
    }

@TEST-END-FILE

@TEST-START-FILE three.bro

redef exit_only_after_terminate = T;

event my_event(s: string)
	{
	print "got my_event", s;
	terminate();
	}

event bro_init()
    {
    Broker::subscribe("bro/event/post-relay");
    Broker::listen("127.0.0.1", 9999/tcp);
    }

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
    {
    print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
    }

@TEST-END-FILE
