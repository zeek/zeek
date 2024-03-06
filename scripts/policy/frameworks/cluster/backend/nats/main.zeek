##! NATS cluster backend support.
##!
##! To actually establish a connection to a NATS cluster, you also want to
##! load load nats/connect.zeek which installs zeek_init() and zeek_done()
##! handlers.

module Cluster::Backend::NATS;

export {
	const url = "nats://localhost:4222" &redef;

	## A publishing connection should not see it's own messages.
	## By default, a NATS consumer sees its own messages, but i
	## believe that this is not the case for broker.
	const no_echo = T &redef;

	## Send messages immediately. By default, prefer higher
	## throughput of latency. Seems ASAP even when false ;-)
	const send_asap = F &redef;

	## Internal event announcing presence of a node.
	global hello: event(name: string, id: string);

	## Internal event announcing shutdown of a node.
	##
	## This event is not guaranteed. A node freezing and being
	## killed or creashing will have no opportunity notifying
	## other nodes about its departure from the cluster.
	global goodbye: event(name: string, id: string);

	## Where Cluster::NATS::hello() and Cluster::NATS::goodbye()
	## events are published to.
	global discovery_topic = "zeek.cluster.discovery" &redef;
	global node_topic_prefix = "zeek.cluster.node" &redef;
	global nodeid_topic_prefix = "zeek.cluster.nodeid" &redef;

	## Whether to subscribe to the logger queue and handle
	## log messages.
	global logger_queue_consume = F &redef;

	## Name of the queue group used by loggers.
	global logger_queue_name = "zeek.logs" &redef;

	## Subject prefix for queue group used by loggers.
	##
	## Subscription will be done on this prefix + ">" and
	## publishes go to {prefix}{stream}.{filter_name}.{path}.
	## If this needs to be more configurable, maybe a callback
	## could be introduced, but for now this seems good enough.
	global logger_queue_subject_prefix = "zeek.logs." &redef;

	## Raised by the NATS backend when the connection to the broker
	## has been established for the first time.
	global connected: event();

	## Raised when the connection to the NATS server was lost.
	global disconnected: event();

	## Raised when the connection to the NATS server was re-established.
	global reconnected: event();
}

# Actually use NATS
redef Cluster::backend = Cluster::CLUSTER_BACKEND_NATS;

# Logger or manager subscribes to the logging queue.
redef logger_queue_consume = Cluster::local_node_type() == Cluster::LOGGER || ( Cluster::manager_is_logger && Cluster::local_node_type() == Cluster::MANAGER );

function nats_node_topic(name: string): string {
	return node_topic_prefix + "." + name;
}

function nats_nodeid_topic(id: string): string {
	return nodeid_topic_prefix + "." + id;
}

# Unique identifier for this node with some debug information.
const my_node_id = fmt("nats_%s_%s_%s",  gethostname(), getpid(), unique_id("N"));

function nats_node_id(): string {
	return my_node_id;
}

# NATS uses subjects that are dot separated
# and not just prefix matching.
redef Cluster::node_topic = nats_node_topic;
redef Cluster::nodeid_topic = nats_nodeid_topic;
redef Cluster::node_id = nats_node_id;

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


event Cluster::Backend::NATS::connected()
	{
	if ( ! Cluster::subscribe(discovery_topic) )
		Reporter::error("Failed to subscribe to discovery topic");

	Cluster::publish(discovery_topic, Cluster::Backend::NATS::hello, Cluster::node, Cluster::node_id());
	}

event Cluster::Backend::NATS::reconnected()
	{
	# Upon a re-connect, just say hello again so other node
	# see a Cluster::node_up() and possibly Cluster::node_down()
	# if they restarted or so.
	Cluster::publish(discovery_topic, Cluster::Backend::NATS::hello, Cluster::node, Cluster::node_id());
	}

# Some node announced itself on the discovery topic, reply with
# Cluster::hello() so it knows we're here, too :-)
event Cluster::Backend::NATS::hello(name: string, id: string)
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

	Cluster::publish(Cluster::nodeid_topic(id), Cluster::hello, Cluster::node, Cluster::node_id());

	event Cluster::hello(name, id);
	}

# Some node properly said bye on the discovery topic, raise node_down()
event Cluster::Backend::NATS::goodbye(name: string, id: string)
	{
	if ( name !in Cluster::nodes )
		{
		Reporter::warning(fmt("goodbye from unexpected node '%s' id: %s", name, id));
		return;
		}

	event Cluster::node_down(name, id);
	}
