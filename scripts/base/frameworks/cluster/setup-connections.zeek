##! This script establishes communication among all nodes in a cluster
##! as defined by :zeek:id:`Cluster::nodes`.

@load ./main
@load ./pools
@load base/frameworks/broker

module Cluster;

export {
	## This hook is called when the local node connects to other nodes based on
	## the given cluster layout. Breaking from the hook will prevent connection
	## establishment.
	##
	## connectee: The node to connect to.
	global connect_node_hook: hook(connectee: NamedNode);
}

function connect_peer(node_type: NodeType, node_name: string)
	{
	local nn = nodes_with_type(node_type);

	for ( i in nn )
		{
		local n = nn[i];

		if ( n$name != node_name )
			next;
		if ( ! hook connect_node_hook(n) )
			return;

		local status = Broker::peer(cat(n$node$ip), n$node$p,
		                            Cluster::retry_interval);
		Cluster::log(fmt("initiate peering with %s:%s, retry=%s, status=%s",
		                 n$node$ip, n$node$p, Cluster::retry_interval,
		                 status));
		return;
		}

	Reporter::warning(fmt("connect_peer: node '%s' (%s) not found", node_name, node_type));
	}

function connect_peers_with_type(node_type: NodeType)
	{
	local nn = nodes_with_type(node_type);

	for ( i in nn )
		{
		local n = nn[i];

		if ( ! hook connect_node_hook(n) )
			next;

		local status = Broker::peer(cat(n$node$ip), n$node$p,
		                            Cluster::retry_interval);
		Cluster::log(fmt("initiate peering with %s:%s, retry=%s, status=%s",
		                 n$node$ip, n$node$p, Cluster::retry_interval,
		                 status));
		}
	}

# Connect to all nodes that have the same type.
#
# To limit the number of connections within a cluster, the logic is to
# connect to all nodes of the same type with a name sorted higher than
# this nodes name itself.
#
# With 3 workers, worker-1 connects to worker-2 and worker-3, worker-2
# connects to worker-3 and worker-3 establishes no extra connections.
function connect_peers_same_type(self_name: string, self_type: Cluster::NodeType)
	{
	# nnodes is already sorted by name.
	local nnodes = nodes_with_type(self_type);

	local idx = -1;
	# nnodes.indexOf(self_name)
	for ( i, nn in nnodes )
		if ( nn$name == self_name )
			idx = i;

	assert idx >= 0, fmt("%s not in %s", self_name, nnodes);

	# Establish a connection to all nodes at higher indices.
	idx += 1;
	while ( idx < |nnodes| )
		{
		connect_peer(self_type, nnodes[idx]$name);
		idx += 1;
		}
	}

event zeek_init() &priority=-10
	{
	if ( getenv("ZEEKCTL_CHECK_CONFIG") != "" )
		return;

	local self = nodes[node];

	for ( i in registered_pools )
		{
		local pool = registered_pools[i];

		if ( node in pool$nodes )
			Cluster::subscribe(pool$spec$topic);
		}

	switch ( self$node_type ) {
	case NONE:
		return;
	case CONTROL:
		break;
	case LOGGER:
		Cluster::subscribe(Cluster::logger_topic);
		break;
	case MANAGER:
		Cluster::subscribe(Cluster::manager_topic);
		break;
	case PROXY:
		Cluster::subscribe(Cluster::proxy_topic);
		break;
	case WORKER:
		Cluster::subscribe(Cluster::worker_topic);
		break;
	default:
		Reporter::error(fmt("Unhandled cluster node type: %s", self$node_type));
		return;
	}

	Cluster::subscribe(nodeid_topic(Cluster::node_id()));
	Cluster::subscribe(node_topic(node));


	# Listening and connecting to other peers is broker specific,
	# short circuit if Zeek is configured with a different
	# cluster backend.
	#
	# In the future, this could move into a policy script, but
	# for the time being it's easier for backwards compatibility
	# to keep this here.
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	# Logging setup: Anything handling logging additionally subscribes
	# to Broker::default_log_topic_prefix.
	switch ( self$node_type ) {
	case LOGGER:
		Cluster::subscribe(Broker::default_log_topic_prefix);
		break;
	case MANAGER:
		if ( Cluster::manager_is_logger )
			Cluster::subscribe(Broker::default_log_topic_prefix);
		break;
	}

	if ( self$p != 0/unknown )
		{
		Broker::listen(Broker::default_listen_address,
		               self$p,
		               Broker::default_listen_retry);

		Cluster::log(fmt("listening on %s:%s", Broker::default_listen_address, self$p));
		}


	switch ( self$node_type ) {
	case MANAGER:
		connect_peers_with_type(LOGGER);

		break;
	case PROXY:
		connect_peers_with_type(LOGGER);

		if ( self?$manager )
			connect_peer(MANAGER, self$manager);

		break;
	case WORKER:
		connect_peers_with_type(LOGGER);
		connect_peers_with_type(PROXY);

		if ( self?$manager )
			connect_peer(MANAGER, self$manager);

		break;
	}

	if ( Cluster::enable_global_pub_sub )
		connect_peers_same_type(node, self$node_type);
	}
