# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b -r $TRACES/ticks-dns-1hr.pcap ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

# @TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;

global runs = 0;
global ping: event(msg: string, intended_ts: time);

event zeek_init()
	{
	Broker::subscribe("zeek/event/my_topic");
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	suspend_processing();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("sender added peer: endpoint=%s msg=%s",
		endpoint$network$address, msg);
	continue_processing();
	}

event new_connection(c: connection)
	{
	print fmt(">> Run %s (%D)", ++runs, network_time());

	local e = Broker::make_event(ping, "my-message", network_time());
	Broker::publish("zeek/event/my_topic", e);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("sender lost peer: endpoint=%s msg=%s",
	endpoint$network$address, msg);
	terminate();
	}

# @TEST-END-FILE


# @TEST-START-FILE recv.zeek

redef exit_only_after_terminate = T;

global msg_count = 0;

event zeek_init()
		{
		Broker::subscribe("zeek/event/my_topic");
		Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
		}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
		{
		print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
		}

event ping(msg: string, intended_ts: time)
	{
	print fmt("receiver got ping: %s intended for %D stamped to %D (is_remote = %s)",
		msg, intended_ts, current_event_time(), is_remote_event());

	if ( ++msg_count >= 10 )
		terminate();
	}

# @TEST-END-FILE
