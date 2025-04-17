# @TEST-DOC: Use Cluster::subscribe() and Cluster::publish() with Broker
# @TEST-GROUP: cluster
#
# @TEST-PORT: BROKER_PORT
#
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b ../send.zeek >send.out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

# @TEST-START-FILE send.zeek

redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;
redef exit_only_after_terminate = T;

global event_count = 0;

global ping: event(msg: string, c: count);

event zeek_init()
	{
	Cluster::init();
	Broker::peer("127.0.0.1", to_port(getenv("BROKER_PORT")));

	Cluster::subscribe("zeek/event/my_topic");
	}

function send_event()
	{
	++event_count;
	local e = Cluster::make_event(ping, "my-message", event_count);
	Cluster::publish("zeek/event/my_topic", e);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("sender added peer: endpoint=%s msg=%s",
	endpoint$network$address, msg);
	send_event();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("sender lost peer: endpoint=%s msg=%s",
	endpoint$network$address, msg);
	Cluster::unsubscribe("zeek/event/my_topic");
	terminate();
	}

event pong(msg: string, n: count)
	{
	print "is_remote should be T, and is", is_remote_event();
	print fmt("sender got pong: %s, %s", msg, n);
	send_event();
	}

# @TEST-END-FILE


# @TEST-START-FILE recv.zeek

redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;
redef exit_only_after_terminate = T;

const events_to_recv = 5;

global handler: event(msg: string, c: count);
global auto_handler: event(msg: string, c: count);

global pong: event(msg: string, c: count);

event zeek_init()
	{
	Cluster::init();
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));

	Cluster::subscribe("zeek/event/my_topic");
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("receiver added peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	print fmt("receiver lost peer: endpoint=%s msg=%s", endpoint$network$address, msg);
	}

event ping(msg: string, n: count)
	{
	print "is_remote should be T, and is", is_remote_event();
	print fmt("receiver got ping: %s, %s", msg, n);

	if ( n == events_to_recv )
		{
		Cluster::unsubscribe("zeek/event/my_topic");
		terminate();
		return;
		}

	Cluster::publish("zeek/event/my_topic", pong, msg, n);
	}
# @TEST-END-FILE
