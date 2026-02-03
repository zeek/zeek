##! Experimental features of the Cluster framework.

@load base/frameworks/cluster

module Cluster::Experimental;

export {
	## When using broker-enabled cluster framework, this event will be sent to
	## the manager and raised locally, once a cluster node has successfully
	## conducted cluster-level handshakes for all its outgoing connections to
	## other cluster nodes based on the given cluster layout.
	##
	## For non-Broker cluster backends, this event is published by a node once
	## it has received Cluster::node_up() from all other nodes in a cluster.
	##
	## name: The name of the now fully connected node.
	##
	## id: The identifier of the now fully connected node.
	##
	## resending: If true, the node has previously signaled that it is fully
	##            connected. This may happen in case the manager restarts.
	##
	## .. warning::
	##
	##     There is no tracking of cluster node connectivity. Thus, there is
	##     no guarantee that all peerings still exist at the time of this event
	##     being raised.
	global node_fully_connected: event(name: string, id: string, resending: bool);

	## When using broker-enabled cluster framework, this event will be
	## broadcasted from the manager once all nodes reported that they have set
	## up all their outgoing connections to other cluster nodes based on the
	## given cluster layout.
	##
	## For non-Broker cluster backends, this event is published when all nodes
	## in a cluster have sent node_fully_connected() to the manager.
	##
	## .. warning::
	##
	##     There is no tracking of cluster node connectivity. Thus, there is
	##     no guarantee that all peerings still exist at the time of this event
	##     being raised.
	global cluster_started: event();


	## The topic to which the cluster_started() event is published.
	const cluster_started_topic = "zeek/cluster/experimental/started" &redef;
}

# Track the names of cluster nodes we expect a Cluster::node_up() from.
#
# This is either populated via Cluster::connect_node_hook() when Broker is the
# selected cluster backend, or otherwise in a zeek_init() handler with all nodes
# from Cluster::nodes except self.
global connectees_pending: set[string];

# Track whether the cluster reached the fully connected state.
global is_cluster_started = F;

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./nodes-experimental/manager
@endif

# Broker specific. Doesn't run for other cluster backends.
hook Cluster::connect_node_hook(connectee: Cluster::NamedNode)
	{
	assert Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER;
	add connectees_pending[connectee$name];
	}

event zeek_init()
	{
	# All nodes subscribe to a cluster_started specific topic. This also works
	# for Broker as it is the manager that sends out the cluster_started() event.
	Cluster::subscribe(cluster_started_topic);
	}

event Cluster::node_up(name: string, id: string) &priority=-10
	{
	# Do not do this for non-Broker backends. This is all Broker specific
	# and the code won't be easier trying to combine them.
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	# Track pending connectees to trigger node_fully_connected, which will be
	# auto published to the manager once available.
	local mgr = Cluster::nodes[Cluster::node]?$manager ? Cluster::nodes[Cluster::node]$manager : "";
	if ( name !in connectees_pending && name != mgr )
		return;

	# At this point we are either awaiting the started node or see our manager
	# for the first time. Hence, we can trigger node_fully_connected if no
	# pending connectee is left.
	delete connectees_pending[name];
	if ( |connectees_pending| == 0 )
		{
		event node_fully_connected(Cluster::node, Cluster::node_id(), is_cluster_started);
		Cluster::publish(Cluster::manager_topic, node_fully_connected,
		                 Cluster::node, Cluster::node_id(), is_cluster_started);
		}
	}

event Cluster::Experimental::node_fully_connected(name: string, id: string, resending: bool)
	{
	if ( ! is_remote_event() )
		Cluster::log("fully connected");
	}

event Cluster::Experimental::cluster_started()
	{
	is_cluster_started = T;
	}


# Below is the node_fully_connected() logic for non-Broker cluster backends. Crucially,
# the assumption is that non-Broker backends provide global pub/sub visibility. That is,
# every node in a cluster sees Cluster::node_up() for every other node.
#
# A node sends Cluster::Experimental::node_fully_connected() to the manager when it has
# seen Cluster::node_up() events from all other nodes in a cluster. We stick with the
# node_fully_connected() event name and the connectees_pending variable name for historic
# reasons. Connections between nodes in a cluster are an implementation detail, however.
# Indeed, with ZeroMQ there's no direct connection between nodes for pub/sub functionality
# anymore (there is direct push/pull connections for logging, but that's separate).
# Instead, they all connect to a central XPUB/XSUB broker.
#
# The manager code handling node_fully_connected() is in nodes-experimental/manager.zeek.
#
# When any node in the cluster restarts and Cluster::node_up() events are raised, all
# other nodes send node_fully_connected() to the manager again. They set the resending
# flag to ``T`` if they've previously observed cluster_started(). The manager will
# not raise another cluster_started() event when it observes the resending
# flag as ``T`` when itself spuriously restarted.

event zeek_init()
	{
	# Broker does not have global pub/sub visibility, see the code
	# above for its logic.
	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
		return;

	# Simply await Cluster::node_up() from all nodes in a cluster, except self.
	for ( name, _ in Cluster::nodes )
		if ( name != Cluster::node )
			add connectees_pending[name];
	}

event Cluster::node_up(name: string, id: string)
	{
	# Broker does not have global pub/sub visibility, see the code
	# above for its logic.
	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
		return;

	delete connectees_pending[name];

	if ( |connectees_pending| == 0 )
		{
		event node_fully_connected(Cluster::node, Cluster::node_id(), is_cluster_started);

		Cluster::publish(Cluster::manager_topic,
		                 Cluster::Experimental::node_fully_connected,
		                 Cluster::node,
		                 Cluster::node_id(),
		                 is_cluster_started);
		}
	}
@endif
