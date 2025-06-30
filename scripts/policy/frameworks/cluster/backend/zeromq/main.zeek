##! ZeroMQ cluster backend support.
##!
##! For publish-subscribe functionality, one node in the Zeek cluster spawns a
##! thread running a central broker listening on a XPUB and XSUB socket.
##! These sockets are connected via `zmq_proxy() <https://libzmq.readthedocs.io/en/latest/zmq_proxy.html>`_.
##! All other nodes connect to this central broker with their own XSUB and
##! XPUB sockets, establishing a global many-to-many publish-subscribe system
##! where each node sees subscriptions and messages from all other nodes in a
##! Zeek cluster. ZeroMQ's `publish-subscribe pattern <http://api.zeromq.org/4-2:zmq-socket#toc9>`_
##! documentation may be a good starting point. Elsewhere in ZeroMQ's documentation,
##! the central broker is also called `forwarder <http://api.zeromq.org/4-2:zmq-proxy#toc5>`_.
##!
##! For remote logging functionality, the ZeroMQ `pipeline pattern <http://api.zeromq.org/4-2:zmq-socket#toc14>`_
##! is used. All logger nodes listen on a PULL socket. Other nodes connect
##! via PUSH sockets to all of the loggers. Concretely, remote logging
##! functionality is not publish-subscribe, but instead leverages ZeroMQ's
##! built-in load-balancing functionality provided by PUSH and PULL
##! sockets.
##!
##! The ZeroMQ cluster backend technically allows to run a non-Zeek central
##! broker (it only needs to offer XPUB and XSUB sockets). Further, it is
##! possible to run non-Zeek logger nodes. All a logger node needs to do is
##! open a ZeroMQ PULL socket and interpret the format used by Zeek nodes
##! to send their log writes.

@load base/utils/addrs

module Cluster::Backend::ZeroMQ;

export {
	## The central broker's XPUB endpoint to connect to.
	##
	## A node connects with its XSUB socket to the XPUB socket
	## of the central broker.
	const connect_xpub_endpoint = "tcp://127.0.0.1:5556" &redef;


	## The central broker's XSUB endpoint to connect to.
	##
	## A node connects with its XPUB socket to the XSUB socket
	## of the central broker.
	const connect_xsub_endpoint = "tcp://127.0.0.1:5555" &redef;

	## Vector of ZeroMQ endpoints to connect to for logging.
	##
	## A node's PUSH socket used for logging connects to each
	## of the ZeroMQ endpoints listed in this vector.
	const connect_log_endpoints: vector of string &redef;

	## Toggle for running a central ZeroMQ XPUB-XSUB broker on this node.
	##
	## If set to ``T``, :zeek:see:`Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread`
	## is called during :zeek:see:`zeek_init`. The node will listen
	## on :zeek:see:`Cluster::Backend::ZeroMQ::listen_xsub_endpoint` and
	## :zeek:see:`Cluster::Backend::ZeroMQ::listen_xpub_endpoint` and
	## forward subscriptions and messages between nodes.
	##
	## By default, this is set to ``T`` on the manager and ``F`` elsewhere.
	const run_proxy_thread: bool = F &redef;

	## How many IO threads to configure for the ZeroMQ context that
	## acts as a central broker.

	## See ZeroMQ's `ZMQ_IO_THREADS documentation <http://api.zeromq.org/4-2:zmq-ctx-set#toc4>`_
	## and the `I/O threads <https://zguide.zeromq.org/docs/chapter2/#I-O-Threads>`_
	## section in the ZeroMQ guide for details.
	const proxy_io_threads = 2 &redef;

	## XSUB listen endpoint for the central broker.
	##
	## This setting is used for the XSUB socket of the central broker started
	## when :zeek:see:`Cluster::Backend::ZeroMQ::run_proxy_thread` is ``T``.
	const listen_xsub_endpoint = "tcp://127.0.0.1:5556" &redef;

	## XPUB listen endpoint for the central broker.
	##
	## This setting is used for the XPUB socket of the central broker started
	## when :zeek:see:`Cluster::Backend::ZeroMQ::run_proxy_thread` is ``T``.
	const listen_xpub_endpoint = "tcp://127.0.0.1:5555" &redef;

	## PULL socket address to listen on for log messages.
	##
	## If empty, don't listen for log messages, otherwise
	## a ZeroMQ address to bind to. E.g., ``tcp://127.0.0.1:5555``.
	const listen_log_endpoint = "" &redef;

	## Configure the ZeroMQ's sockets linger value.
	##
	## The default used by libzmq is 30 seconds (30 000) which is very long
	## when loggers vanish before workers during a shutdown, so we reduce
	## this to 500 milliseconds by default.
	##
	## A value of ``-1`` configures blocking forever, while ``0`` would
	## immediately discard any pending messages.
	##
	## See ZeroMQ's `ZMQ_LINGER documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc24>`_
	## for more details.
	const linger_ms: int = 500 &redef;

	## Send high water mark value for the XPUB socket.
	##
	## If reached, Zeek nodes will block or drop messages.
	##
	## See ZeroMQ's `ZMQ_SNDHWM documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc46>`_
	## for more details.
	const xpub_sndhwm: int = 1000 &redef;

	## Kernel transmit buffer size for the XPUB socket.
	##
	## Using -1 will use the kernel's default.
	##
	## See ZeroMQ's `ZMQ_SNDBUF documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc45>`_
	## for more details.
	const xpub_sndbuf: int = -1 &redef;

	## Receive high water mark value for the XSUB socket.
	##
	## If reached, the Zeek node will start reporting back pressure
	## to the central XPUB socket.
	##
	## See ZeroMQ's `ZMQ_RCVHWM documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc35>`_
	## for more details.
	const xsub_rcvhwm: int = 1000 &redef;

	## Kernel receive buffer size for the XSUB socket.
	##
	## Using -1 will use the kernel's default.
	##
	## See ZeroMQ's `ZMQ_RCVBUF documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc34>`_
	## for more details.
	const xsub_rcvbuf: int = -1 &redef;

	## Configure ZeroMQ's immediate setting on PUSH sockets
	##
	## Setting this to ``T`` will queue log writes only to completed
	## connections. By default, log writes are queued to all potential
	## endpoints listed in :zeek:see:`Cluster::Backend::ZeroMQ::connect_log_endpoints`.
	##
	## See ZeroMQ's `ZMQ_IMMEDIATE documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc21>`_
	## for more details.
	const log_immediate: bool = F &redef;

	## Send high water mark value for the log PUSH sockets.
	##
	## If reached, Zeek nodes will block or drop messages.
	##
	## See ZeroMQ's `ZMQ_SNDHWM documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc46>`_
	## for more details.
	##
	## TODO: Make action configurable (block vs drop)
	const log_sndhwm: int = 1000 &redef;

	## Receive high water mark value for the log PULL sockets.
	##
	## If reached, Zeek workers will block or drop messages.
	##
	## See ZeroMQ's `ZMQ_RCVHWM documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc35>`_
	## for more details.
	##
	## TODO: Make action configurable (block vs drop)
	const log_rcvhwm: int = 1000 &redef;

	## Kernel transmit buffer size for log sockets.
	##
	## Using -1 will use the kernel's default.
	##
	## See ZeroMQ's `ZMQ_SNDBUF documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc45>`_.
	const log_sndbuf: int = -1 &redef;

	## Kernel receive buffer size for log sockets.
	##
	## Using -1 will use the kernel's default.
	##
	## See ZeroMQ's `ZMQ_RCVBUF documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc34>`_
	## for more details.
	const log_rcvbuf: int = -1 &redef;

	## Set ZMQ_IPV6 option.
	##
	## The ZeroMQ library has IPv6 support in ZeroMQ. For Zeek we enable it
	## unconditionally such that listening or connecting  with IPv6 just works.
	##
	## See ZeroMQ's `ZMQ_IPV6 documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc23>`_
	## for more details.
	const ipv6 = T &redef;

	## Do not silently drop messages if high-water-mark is reached.
	##
	## Whether to configure ``ZMQ_XPUB_NODROP`` on the XPUB socket
	## connecting to the proxy to detect when sending a message fails
	## due to reaching the high-water-mark.
	##
	## See ZeroMQ's `ZMQ_XPUB_NODROP documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc61>`_
	## for more details.
	const connect_xpub_nodrop: bool = T &redef;

	## Do not silently drop messages if high-water-mark is reached.
	##
	## Whether to configure ``ZMQ_XPUB_NODROP`` on the XPUB socket
	## to detect when sending a message fails due to reaching
	## the high-water-mark.
	##
	## This setting applies to the XPUB/XSUB broker started when
	## :zeek:see:`Cluster::Backend::ZeroMQ::run_proxy_thread` is ``T``.
	##
	## See ZeroMQ's `ZMQ_XPUB_NODROP documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc61>`_
	## for more details.
	const listen_xpub_nodrop: bool = T &redef;

	## Messages to receive before yielding.
	##
	## Yield from the receive loop when this many messages have been
	## received from one of the used sockets.
	const poll_max_messages = 100 &redef;

	## Bitmask to enable low-level stderr based debug printing.
	##
	##     poll:   1 (produce verbose zmq::poll() output)
	##     thread: 2 (produce thread related output)
	##
	## Or values from the above list together and set debug_flags
	## to the result. E.g. use 7 to select 4, 2 and 1. Only use this
	## in development if something seems off. The thread used internally
	## will produce output on stderr.
	const debug_flags: count = 0 &redef;

	## The node topic prefix to use.
	global node_topic_prefix = "zeek.cluster.node" &redef;

	## The node_id topic prefix to use.
	global nodeid_topic_prefix = "zeek.cluster.nodeid" &redef;

	## Low-level event when a subscription is added.
	##
	## Every node observes all subscriptions from other nodes
	## in a cluster through its XPUB socket. Whenever a new
	## subscription topic is added, this event is raised with
	## the topic.
	##
	## topic: The topic.
	global subscription: event(topic: string);

	## Low-level event when a subscription vanishes.
	##
	## Every node observes all subscriptions from other nodes
	## in a cluster through its XPUB socket. Whenever a subscription
	## is removed from the local XPUB socket, this event is raised
	## with the topic set to the removed subscription.
	##
	## topic: The topic.
	global unsubscription: event(topic: string);

	## Low-level event send to a node in response to their subscription.
	##
	## name: The sending node's name in :zeek:see:`Cluster::nodes`.
	##
	## id: The sending node's identifier, as generated by :zeek:see:`Cluster::node_id`.
	global hello: event(name: string, id: string);

	## Expiration for hello state.
	##
	## How long to wait before expiring information about
	## subscriptions and hello messages from other
	## nodes. These expirations trigger reporter warnings.
	const hello_expiration: interval = 10sec &redef;

	## The topic prefix used for internal ZeroMQ specific communication.
	##
	## This is used for the "ready to publish callback" topics.
	##
	## Zeek creates a short-lived subscription for a auto-generated
	## topic name with this prefix and waits for it to be confirmed
	## on its XPUB socket. Once this happens, the XPUB socket should've
	## also received all other active subscriptions of other nodes in a
	## cluster from the central XPUB/XSUB proxy and therefore can be
	## deemed ready for publish operations.
	const internal_topic_prefix = "zeek.zeromq.internal." &redef;
}

redef Cluster::backend = Cluster::CLUSTER_BACKEND_ZEROMQ;

# By default, let the manager node run the proxy thread.
redef run_proxy_thread = Cluster::local_node_type() == Cluster::MANAGER;

function zeromq_node_topic(name: string): string {
	return node_topic_prefix + "." + name + ".";
}

function zeromq_nodeid_topic(id: string): string {
	return nodeid_topic_prefix + "." + id + ".";
}

redef Cluster::Telemetry::topic_normalizations += {
	[/^zeek\.cluster\.nodeid\..*/] = "zeek.cluster.nodeid.__normalized__",
};

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
redef listen_log_endpoint = fmt("tcp://%s:%s", addr_to_uri(my_node$ip), port_to_count(my_node$p));
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
			endp = fmt("tcp://%s:%s", addr_to_uri(node$ip), port_to_count(node$p));
			connect_log_endpoints += endp;
			}

		if ( Cluster::manager_is_logger && node$node_type == Cluster::MANAGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", node$ip, port_to_count(node$p));
			connect_log_endpoints += endp;
			}
		}

	# If there's no endpoints configured, but more than a single
	# node in cluster layout, log an error as that's probably not
	# an intended configuration.
	if ( |connect_log_endpoints| == 0 && |Cluster::nodes| > 1 )
		Reporter::error("No ZeroMQ connect_log_endpoints configured");
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
