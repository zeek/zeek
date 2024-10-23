##! ZeroMQ cluster backend support.
##!
##! For publish-subscribe functionality, one node in the Zeek cluster runs a
##! central proxy listening on XPUB and XSUB sockets that are connected via
##! zmq_proxy(). All other nodes connect to this central proxy process with
##! XSUB and XPUB sockets.
##!
##! For logging, all logger nodes listen on their PULL sockets, all other
##! nodes connect via PUSH sockets to all the logger's PULL sockets.
##!
##! This setup actually allows to run a non-Zeek central proxy (it only needs
##! to offer XPUB and XSUB sockets, but also allows running non-Zeek logger
##! nodes. All a logger node needs to do is open a PULL socket (and understand
##! the format used by Zeek.
module Cluster::Backend::ZeroMQ;

export {
	## How many milliseconds to stall termination to flush
	## out messages on sockets.
	##
	## The default is 30 seconds (30 000) which is very long in zeek -j
	## settings when shutting down loggers before workers.
	const linger_ms: int = 500 &redef;

	## Bitmask to enable fprintf based debug printing.
	##
	##     poll debugging: 1
	const debug_flags: count = 0 &redef;

	## Whether to configure ZMQ_XPUB_NODROP on the xpub socket
	## to detect when sending a message fails due to reaching
	## the HWM.
	const xpub_nodrop: bool = T &redef;

	## On which endpoints should the proxy thread listen?
	## This doesn't need to run in Zeek. It could also be
	## a separate process. But: All nodes need to connect
	## to the same broker thread.
	const listen_xsub_endpoint = "tcp://127.0.0.1:5556" &redef;
	const listen_xpub_endpoint = "tcp://127.0.0.1:5555" &redef;

	## A node connects with its XPUB socket to the XSUB socket
	## of the broker. And its XSUB socket to the XPUB socket
	## of the broker. So its the inverse compared to the above.
	const connect_xpub_endpoint = "tcp://127.0.0.1:5556" &redef;
	const connect_xsub_endpoint = "tcp://127.0.0.1:5555" &redef;

	# Logging

	## Vector of endpoints to connect to for logging. A local
	## PUSH socket is opened and connected to each of them.
	const connect_log_endpoints: vector of string &redef;

	## Queue log writes only to completed connections.
	const log_immediate: bool = F &redef;

	## Send high water mark value for the log PUSH sockets.
	## If reached, Zeek workers will block or drop messages.
	##
	## TODO: Make action configurable (block vs drop)
	const log_sndhwm: int = 1000 &redef;

	## Receive high water mark value for the log PULL sockets.
	## If reached, Zeek workers will block or drop messages.
	##
	## TODO: Make action configurable (block vs drop)
	const log_rcvhwm: int = 1000 &redef;

	## Kernel send and receive buffer sizes. Use -1 as the default.
	const log_sndbuf: int = -1 &redef;
	const log_rcvbuf: int = -1 &redef;

	## Endpoint to listen on for log messages. If empty,
	## don't listen.
	const listen_log_endpoint = "" &redef;

	# Whether to run the zmq_proxy() thread on this node.
	const run_proxy_thread: bool = F &redef;

	global node_topic_prefix = "zeek.cluster.node" &redef;
	global nodeid_topic_prefix = "zeek.cluster.nodeid" &redef;

	## Low level event when a subscription arrived on a node's
	## XPUB socket. This can be used to reply with Cluster::hello()
	## on that node.
	global subscription: event(topic: string);

	## Low level event when nodes unsubscribe.
	global unsubscription: event(topic: string);

	global hello: event(name: string, id: string);

	## How long before expiring information about
	## subscriptions and hello messages from other
	## nodes.
	const hello_expiration: interval = 10sec &redef;
}

redef Cluster::backend = Cluster::CLUSTER_BACKEND_ZEROMQ;

function zeromq_node_topic(name: string): string {
	return node_topic_prefix + "." + name;
}

function zeromq_nodeid_topic(id: string): string {
	return nodeid_topic_prefix + "." + id;
}

# Unique identifier for this node with some debug information.
const my_node_id = fmt("zeromq_%s_%s_%s_%s",  Cluster::node, gethostname(), getpid(), unique_id("N"));

function zeromq_node_id(): string {
	return my_node_id;
}

redef Cluster::node_topic = zeromq_node_topic;
redef Cluster::nodeid_topic = zeromq_nodeid_topic;
redef Cluster::node_id = zeromq_node_id;

redef Cluster::logger_topic = "zeek.cluster.logger";
redef Cluster::manager_topic = "zeek.cluster.manager";
redef Cluster::proxy_topic = "zeek.cluster.proxy";
redef Cluster::worker_topic = "zeek.cluster.worker";

redef Cluster::proxy_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.proxy",
	$node_type = Cluster::PROXY);

redef Cluster::logger_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.logger",
	$node_type = Cluster::LOGGER);

redef Cluster::worker_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.worker",
	$node_type = Cluster::WORKER);


# Configure listen_log_endpoint based on port in cluster-layout, if any.
@if ( Cluster::local_node_type() == Cluster::LOGGER || (Cluster::manager_is_logger && Cluster::local_node_type() == Cluster::MANAGER) )
const my_node = Cluster::nodes[Cluster::node];
@if ( my_node?$p )
redef listen_log_endpoint = fmt("tcp://%s:%s", my_node$ip, port_to_count(my_node$p));
@endif
@endif

# Populate connect_log_endpoints based on Cluster::nodes on non-logger nodes.
# If you're experimenting with zero-logger clusters, ignore this code and set
# connect_log_endpoints yourself via redef.
event zeek_init() &priority=100
	{
	if ( Cluster::local_node_type() == Cluster::LOGGER )
		return;

	if ( Cluster::manager_is_logger && Cluster::local_node_type() == Cluster::MANAGER )
		return;

	for ( _, node in Cluster::nodes )
		{
		local endp: string;
		if ( node$node_type == Cluster::LOGGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", node$ip, port_to_count(node$p));
			connect_log_endpoints += endp;
			}

		if ( Cluster::manager_is_logger && node$node_type == Cluster::MANAGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", node$ip, port_to_count(node$p));
			connect_log_endpoints += endp;
			}
		}

	# If there's no endpoints configured, but more than a single
	# node in cluster layout, log an error, that's probably not
	# intended.
	if ( |connect_log_endpoints| == 0 && |Cluster::nodes| > 1 )
		Reporter::error("No ZeroMQ connect_log_endpoints configured");
	}

# By default, let the manager node run the proxy thread.
redef run_proxy_thread = Cluster::local_node_type() == Cluster::MANAGER;


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

# The ZeroMQ plugin notifies script land when a subscription arrived
# on the XPUB socket. If such a subscription starts with the nodeid_topic_prefix,
# send a ZeroMQ::hello() event to it, announcing the presence of this
# node to the one that created the subscriptions. This goes in both directions,
# the other node will see the subscription incoming from existing or new nodes
# and publish ZeroMQ::hello() as well. So every node says hello to all other
# nodes.
event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	local prefix = nodeid_topic_prefix + ".";
	if ( starts_with(topic, prefix) )
		{
		Cluster::publish(topic, Cluster::Backend::ZeroMQ::hello, Cluster::node, Cluster::node_id());
		local nodeid = topic[|prefix|:];
		add nodeid_subscriptions[nodeid];

		if ( nodeid in nodeid_hellos )
			{
			Cluster::publish(Cluster::nodeid_topic(nodeid), Cluster::hello, Cluster::node, Cluster::node_id());
			delete nodeid_hellos[nodeid];
			delete nodeid_subscriptions[nodeid];
			}
		}
	}

# Receiving ZeroMQ::hello() from another node: Raise Cluster::hello()
# locally to trigger local Cluster functionality. Also, if we never saw
# the node go away, log a warning and raise Cluster::node_down().
event Cluster::Backend::ZeroMQ::hello(name: string, id: string)
	{
	if ( name in Cluster::nodes )
		{
		local n = Cluster::nodes[name];
		if ( n?$id )
			{
			Reporter::warning(fmt("node '%s' never said goodbye (old id:%s new id:%s",
			                  name, n$id, id));

			# We raise node_down() here for the old instance,
			# but it's obviously fake and somewhat lying.
			event Cluster::node_down(name, n$id);
			}
		}

	add nodeid_hellos[id];

	# We can only publish here if the other system *also* has
	# a subscription setup, otherwise we can't reach the node.
	if ( id in nodeid_subscriptions )
		{
		Cluster::publish(Cluster::nodeid_topic(id), Cluster::hello, Cluster::node, Cluster::node_id());
		delete nodeid_hellos[id];
		delete nodeid_subscriptions[id];
		}
	}

# If the unsubscription is for a nodeid prefix, extract the
# nodeid that is now gone, find the name of the node from the
# cluster layout and raise Cluster::node_down().
event Cluster::Backend::ZeroMQ::unsubscription(topic: string)
	{
	local prefix = nodeid_topic_prefix + ".";
	if ( ! starts_with(topic, prefix) )
		return;

	local gone_node_id = topic[|prefix|:];
	local name = "<unknown>";
	for ( node_name, n in Cluster::nodes ) {
		if ( n?$id && n$id == gone_node_id ) {
			name = node_name;
			break;
		}
	}

	event Cluster::node_down(name, gone_node_id);
	}
