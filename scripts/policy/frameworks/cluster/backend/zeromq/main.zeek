##! ZeroMQ cluster logic

module Cluster::Backend::ZeroMQ;

@load ./options
@load base/utils/addrs

# Populate connect_log_endpoints based on Cluster::nodes on non-logger nodes.
# If you're experimenting with zero-logger clusters, ignore this code and set
# connect_log_endpoints yourself via redef.
event zeek_init() &priority=100
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_ZEROMQ )
		return;

	if ( Cluster::local_node_type() == Cluster::LOGGER )
		return;

	if ( Cluster::manager_is_logger && Cluster::local_node_type() == Cluster::MANAGER )
		return;

	for ( _, node in Cluster::nodes )
		{
		local endp: string;
		if ( node$node_type == Cluster::LOGGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", addr_to_uri(node$ip), node$p as count);
			connect_log_endpoints += endp;
			}

		if ( Cluster::manager_is_logger && node$node_type == Cluster::MANAGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", node$ip, node$p as count);
			connect_log_endpoints += endp;
			}
		}

	# If there's no endpoints configured, but more than a single
	# node in cluster layout, log an error as that's probably not
	# an intended configuration.
	if ( |connect_log_endpoints| == 0 && |Cluster::nodes| > 1 )
		Reporter::error("No ZeroMQ connect_log_endpoints configured");
	}

event zeek_init() &priority=10
	{
	if ( getenv("ZEEKCTL_CHECK_CONFIG") != "" )
		return;

	# Use ZEEKCTL_DISABLE_LISTEN to skip initialization of anything ZeroMQ related.
	if ( getenv("ZEEKCTL_DISABLE_LISTEN") != "" )
		return;

	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_ZEROMQ )
		return;

	if ( run_proxy_thread )
		{
		if ( ! Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread() )
			Reporter::fatal("Failed to spawn ZeroMQ proxy thread");
		}

	if ( ! Cluster::init() )
		Reporter::fatal("Failed initialize ZeroMQ backend");
	}

function nodeid_subscription_expired(nodeids: set[string], nodeid: string): interval
	{
	Reporter::warning(fmt("Expired subscription from nodeid %s", nodeid));
	return 0.0sec;
	}

function nodeid_hello_expired(nodeids: set[string], nodeid: string): interval
	{
	Reporter::warning(fmt("Expired hello from nodeid %s", nodeid));
	return 0.0sec;
	}

# State about subscriptions and hellos seen from other nodes.
global nodeid_subscriptions: set[string] &create_expire=hello_expiration &expire_func=nodeid_subscription_expired;
global nodeid_hellos: set[string] &create_expire=hello_expiration &expire_func=nodeid_hello_expired;

# The ZeroMQ plugin notifies script land when a new subscription arrived
# on that node's XPUB socket. If the topic of such a subscription starts with
# the nodeid_topic_prefix for another node A, node B seeing the subscription
# sends ZeroMQ::hello() to the topic, announcing its own presence to node A.
# Conversely, when node A sees the subscription for node B's nodeid topic,
# it also sens ZeroMQ::hello(). In other words, every node says hello to all
# other nodes based on subscriptions they observe on their local XPUB sockets.
#
# Once node B has seen both, the nodeid topic subscription and ZeroMQ::hello()
# event from node A, it raises a Cluster::node_up() event for node A.
#
# See also the Cluster::Backend::ZeroMQ::hello() handler below.
#
#   1) node A subscribes to Cluster::nodeid_topic(Cluster::node_id())
#   2) node B observes subscription for node A's nodeid_topic and replies with ZeroMQ::hello()
#   3) node A receives node B's nodeid_topic subscription, replies with ZeroMQ::hello()
#   4) node B receives node A's ZeroMQ::hello() and raises Cluster::node_up()
#      as it has already seen node A's nodeid_topic subscription.
event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	local prefix = nodeid_topic_prefix + ".";

	if ( ! starts_with(topic, prefix) )
		return;

	local nodeid = topic[|prefix|:][:-1];

	# Do not say hello to ourselves - we won't see it anyhow.
	if ( nodeid  == Cluster::node_id() )
		return;

	Cluster::publish(topic, Cluster::Backend::ZeroMQ::hello, Cluster::node, Cluster::node_id());

	# If we saw a ZeroMQ::hello from the other node already, send
	# it a Cluster::hello.
	if ( nodeid in nodeid_hellos )
		{
		Cluster::publish(Cluster::nodeid_topic(nodeid), Cluster::hello, Cluster::node, Cluster::node_id());
		delete nodeid_hellos[nodeid];
		}
	else
		{
		add nodeid_subscriptions[nodeid];
		}
	}

# Receiving ZeroMQ::hello() from another node: If we received a subscription
# for the node's nodeid_topic, reply with a Cluster::hello. If the node never
# properly went away, log a warning and raise a Cluster::node_down() now.
event Cluster::Backend::ZeroMQ::hello(name: string, id: string)
	{
	if ( name in Cluster::nodes )
		{
		local n = Cluster::nodes[name];
		if ( n?$id )
			{
			if ( n$id == id )
				{
				# Duplicate ZeroMQ::hello(), very strange, ignore it.
				Reporter::warning(fmt("node '%s' sends ZeroMQ::hello twice (id:%s)",
						  name, id));
				return;
				}

			Reporter::warning(fmt("node '%s' never said goodbye (old id:%s new id:%s",
			                      name, n$id, id));

			# We raise node_down() here for the old instance,
			# but it's obviously fake and somewhat lying.
			event Cluster::node_down(name, n$id);
			}
		}

	# It is possible to publish Cluster::hello() directly if the nodeid_topic
	# subscription for the other node was already seen. Otherwise, remember
	# that Cluster::hello() has been seen and send Cluster::hello() in
	# subscription processing further up.
	if ( id in nodeid_subscriptions )
		{
		Cluster::publish(Cluster::nodeid_topic(id), Cluster::hello, Cluster::node, Cluster::node_id());
		delete nodeid_subscriptions[id];
		}
	else
		{
		add nodeid_hellos[id];
		}
	}

# If the unsubscription is for a nodeid prefix, extract the
# nodeid that's gone, find the name of the node from the
# cluster layout and raise Cluster::node_down().
event Cluster::Backend::ZeroMQ::unsubscription(topic: string)
	{
	local prefix = nodeid_topic_prefix + ".";
	if ( ! starts_with(topic, prefix) )
		return;

	local gone_node_id = topic[|prefix|:][:-1];
	local name = "";
	for ( node_name, n in Cluster::nodes ) {
		if ( n?$id && n$id == gone_node_id ) {
			name = node_name;
			break;
		}
	}

	if ( name != "" )
		event Cluster::node_down(name, gone_node_id);
	else
		Reporter::warning(fmt("unsubscription of unknown node with id '%s'", gone_node_id));
	}

event Cluster::Backend::ZeroMQ::monitoring_event(number: count, value: count, address: string)
	{
	# Anytime we see a handshake failed error (e.g. wrong CURVE keys in use
	# or CURVE socket connecting to non-CURVE sockets), the Zeek process
	# terminates with Reporter::fatal() as this is a configuration error.
	#
	# From zmq.h
	# Unspecified system errors during handshake. Event value is an errno.
	# #define ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL 0x0800
	# Handshake complete successfully with successful authentication (if enabled). Event value is unused.
	# #define ZMQ_EVENT_HANDSHAKE_SUCCEEDED 0x1000
	# Protocol errors between ZMTP peers or between server and ZAP handler.
	# Event value is one of ZMQ_PROTOCOL_ERROR
	# #define ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL 0x2000
	# Failed authentication requests. Event value is the numeric ZAP status
	# code, i.e. 300, 400 or 500.
	# #define ZMQ_EVENT_HANDSHAKE_FAILED_AUTH 0x4000

	# We don't treat 0x0800 as fatal as this can happen when there's
	# connection errors during the handshake. Hard-exiting the process
	# is a bit too much in that case.
	if ( number == 0x0800 )
		Reporter::warning(fmt("ZeroMQ: Handshake for socket %s failed: event=0x%x value=%s", address, number, value));

	if ( number == 0x2000 || number == 0x4000 )
		Reporter::fatal(fmt("ZeroMQ: Handshake for socket %s failed: event=0x%x value=%s", address, number, value));
	}
