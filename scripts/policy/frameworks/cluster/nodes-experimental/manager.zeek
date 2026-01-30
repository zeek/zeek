##! This script is loaded on the cluster manager to cover manager-related
##! parts of experimental features.

@load base/frameworks/cluster
@load policy/frameworks/cluster/experimental

module Cluster::Experimental;

global fully_connected_nodes_pending: set[string];

event zeek_init()
	{
	fully_connected_nodes_pending = table_keys(Cluster::nodes);
	}

event node_fully_connected(name: string, id: string, resending: bool)
	{
	# If a node resends this event, it has already seen the cluster connected.
	# That is, the manager most likely restarted. Adopt the view of the other
	# nodes.
	is_cluster_started = is_cluster_started || resending;

	delete fully_connected_nodes_pending[name];
	if ( !is_cluster_started && |fully_connected_nodes_pending| == 0 )
		{
		event cluster_started();

		Cluster::publish(cluster_started_topic,
		                 Cluster::Experimental::cluster_started);
		}
	}

event cluster_started()
	{
	Cluster::log("cluster connected");
	}

# Handle some special cases for tracking connected nodes:

event zeek_init() &priority=-15
	{
	# Make sure the manager recognizes itself as ready if no
	# connections have to be initiated.
	#
	# This is only needed for Broker. With non-Broker backends, nodes
	# see Cluster::node_up() from all other nodes in a cluster due to
	# global pub/sub reachability.
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	if ( |connectees_pending| == 0 )
		event node_fully_connected(Cluster::node, Cluster::node_id(), F);
	}

event Cluster::node_up(name: string, id: string)
	{
	# Loggers may not know any manager and would thus be unable to
	# report successful setup. As they do not establish connections
	# we can consider this case here.

	# This is only needed for Broker. With non-Broker backends, nodes
	# see Cluster::node_up() from all other nodes in a cluster due to
	# global pub/sub reachability.
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	local n = Cluster::nodes[name];
	if ( n$node_type == Cluster::LOGGER && ! n?$manager )
		event node_fully_connected(name, id, F);
	}
