# @TEST-DOC: Broker::publish() within a schedule event uses the intended timestamp, not the current network_time()
#
# Not compatible with -O C++ testing since includes two distinct scripts.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-GROUP: broker
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b -r $TRACES/ticks-dns-1hr.pcap ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 5
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

# @TEST-START-FILE send.zeek

redef exit_only_after_terminate = T;
redef EventMetadata::add_network_timestamp = T;

global runs = 0;
global ping: event(msg: string, intended_ts: time, publish_ts: time);

event zeek_init()
	{
	suspend_processing();
	Broker::subscribe("zeek/event/my_topic");
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event send_ping(msg: string, intended_ts: time)
	{
	print fmt(">>> Publish %s intended for %D (current_event_time=%D, network_time=%D)",
	          msg, intended_ts, current_event_time(), network_time());
	Broker::publish("zeek/event/my_topic", ping, msg, intended_ts, network_time());
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

	event send_ping("my-message-a", network_time());
	schedule 30 mins { send_ping("my-message-c", network_time() + 30 mins) };
	schedule 15 mins { send_ping("my-message-b", network_time() + 15 mins) };
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
redef EventMetadata::add_network_timestamp = T;

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

event ping(msg: string, intended_ts: time, publish_ts: time) &is_used
	{
	if ( ++msg_count >= 10 )
		{
		terminate();
		return;
		}

	print fmt("receiver got ping: %s intended for %D published at %D stamped to %D (is_remote = %s, intended_equals_stamped=%s)",
		msg, intended_ts, publish_ts, current_event_time(), is_remote_event(), intended_ts == current_event_time());
	}
# @TEST-END-FILE
