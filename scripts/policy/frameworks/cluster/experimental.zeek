##! Experimental features of the Cluster framework.

@load base/frameworks/cluster

module Cluster::Experimental;

export {
	## When using broker-enabled cluster framework, this event will be sent to
	## the manager and raised locally, once a cluster node has successfully
	## conducted cluster-level handshakes for all its outgoing connections to
	## other cluster nodes based on the given cluster layout.
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
	## .. warning::
	##
	##     There is no tracking of cluster node connectivity. Thus, there is
	##     no guarantee that all peerings still exist at the time of this event
	##     being raised.
	global cluster_started: event();
}

# Track the names of cluster nodes, the local node sets up connections to.
global connectees_pending: set[string];
# Track whether the cluster reached the fully connected state.
global is_cluster_started = F;

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./nodes-experimental/manager
@endif

hook Cluster::connect_node_hook(connectee: Cluster::NamedNode)
	{
	add connectees_pending[connectee$name];
	}

event zeek_init()
	{
	## If global publish subscribe is enabled, every cluster node
	## can expect a Cluster::node_up() from other nodes.
	if ( Cluster::enable_global_pub_sub )
		{
		for ( name, _ in Cluster::nodes )
			if ( name != Cluster::node )
				add connectees_pending[name];

		}
	}

event Cluster::node_up(name: string, id: string) &priority=-10
	{
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

@endif
