##! Broker cluster backend support.
##!
##! The Broker cluster backend is a peer-to-peer backend that has been
##! in use since Bro 2.6 and the default until Zeek 8.1. Cluster nodes peer
##! with each other selectively, using a fixed connection strategy based on
##! cluster node types. This information is stored in :zeek:see:`Cluster::nodes`
##! as populated by the cluster-layout.zeek file, or internally via the Supervisor
##! when in use.
##!
##! Conceptually:
##!
##!   * All nodes peer with all logger nodes
##!   * All worker nodes peer with all proxy nodes and the manager node
##!   * All proxy nodes peer with the manager
##!
##! This implies that logger, manager and proxy nodes are all listening
##! on the ports defined in the cluster layout.
##!
##! Note that publish-subscribe visibility with Broker is limited to nodes
##! that are directly peered. A worker publishing a message to a topic another
##! worker node is subscribed to will not be visible by the other worker.

module Cluster;

redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;

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

# Whenever a node adds a Broker peer, it sends Cluster::hello() identifying
# itself to the peer. The other peer then raises Cluster::node_up(), upon
# seeing the Cluster::hello()
event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=10
	{
	if ( ! Cluster::is_enabled() )
		return;

	local e = Broker::make_event(Cluster::hello, node, Cluster::node_id());
	Broker::publish(nodeid_topic(endpoint$id), e);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string) &priority=10
	{
	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == endpoint$id )
			{
			event Cluster::node_down(node_name, endpoint$id);
			break;
			}
		}
	}

# The event handler setting up subscriptions has priority -5. It runs
# before this handler. Priority -10 also means that a user can fiddle
# with the cluster-layout in zeek_init() for testing.
event zeek_init() &priority=-10
	{
	if ( getenv("ZEEKCTL_CHECK_CONFIG") != "" )
		return;

	if ( ! Cluster::is_enabled() )
		return;

	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	local self = Cluster::nodes[Cluster::node];

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
	}
