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

		# As of now, logging and broker are coupled.
		#
		# All nodes connect via broker to all loggers and
		# PublishLogWrite() uses broker directly today. This
		# isn't exactly pub/sub, but rather load balancing
		# across available nodes. Seems this could also be
		# done via ZMQ push/pull sockets more directly, or
		# AMQP or NATS queues. Maybe that's thought too simple,
		# however.
		#
		# Also, if we were to publish log writes to a generic
		# pub sub system, why couldn't that system be the "logger".
		# Keyword zero-logger architecture.
		#
		# Long story short, loggers continue to subscribe explicitly
		# using broker, because the log subsystem relies on that today.
		Broker::subscribe(node_topic(node));
		Broker::subscribe(Broker::default_log_topic_prefix);
		break;
	case MANAGER:
		Cluster::subscribe(Cluster::manager_topic);

		if ( Cluster::manager_is_logger )
			{
			# See motivation above. This is broker dependent.
			Broker::subscribe(node_topic(node));
			Broker::subscribe(Broker::default_log_topic_prefix);
			}

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
