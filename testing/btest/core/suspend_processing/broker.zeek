# @TEST-DOC: Suspend pcap processing on a worker and wait for the manager to trigger continue processing via a broker message. Ensure network_time() is not initialized until continue_processing() is called.
# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run manager "zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker "zeek -r $TRACES/http/get.trace -b ../worker.zeek"
# @TEST-EXEC: btest-bg-wait 5

# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff worker/.stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff manager/.stdout

@TEST-START-FILE worker.zeek

event zeek_init()
	{
	print network_time(), "zeek_init: suspend_processing()";
	suspend_processing();
	}

event zeek_init() &priority=-5
	{
	print network_time(), "zeek_init: broker peering";
        Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	Broker::subscribe("zeek/event/my_topic");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
        {
        print network_time(), "Broker::peer_added";
        }

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
        print network_time(), "[FAIL] Broker::peer_lost";
	}

event do_continue_processing() &is_used
	{
	print network_time(), "do_continue_processing";
	continue_processing();
	}

event network_time_init()
	{
	print network_time(), "network_time_init";
	}

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid, c$id;
	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done", path;
	terminate();
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
@TEST-END-FILE


@TEST-START-FILE manager.zeek
# The manager waits for a peer and directly publishes do_continue_processing()
# to it. It terminates when the peer is lost.
global do_continue_processing: event();

event zeek_init()
	{
	print "manager: listening";
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
        {
        print "manager: peer added, publishing do_continue_processing";
	Broker::publish("zeek/event/my_topic", do_continue_processing);
        }
event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "manager: peer lost, terminating";
	terminate();
	}
@TEST-END-FILE
