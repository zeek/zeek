##! NATS cluster backend support.
##!
##! Cluster::node_down() only works when a node properly
##! says good bye on the discovery topic.
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

	## Raised by the NATS backend when the connection to the broker
	## has been established for the first time.
	global connected: event();

	## Raised when the connection to the NATS server was lost.
	global disconnected: event();

	## Raised when the connection to the NATS server was re-established.
	global reconnected: event();

	## Type to support Cluster::make_event(). Seems to work.
	##
	## The NATS Backend directly works with ValPtrs while the
	## Broker backend used some Broker::Data thing, but I don't
	## see why we need this.
	type Event: record {
		ev: any;
		args: vector of any;
	};
}

# Actually use NATS
redef Cluster::backend = Cluster::CLUSTER_BACKEND_NATS;

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


# Entry point
event zeek_init()
	{
	Cluster::Backend::NATS::connect();
	}

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

event zeek_done() &priority=-100
	{
	# Upon shutdown, send out a goodbye so other nodes can properly
	# raise Cluster::node_down().
	Cluster::publish(discovery_topic, Cluster::Backend::NATS::goodbye, Cluster::node, Cluster::node_id());
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
