##! This script establishes communication among all nodes in a cluster
##! as defined by :zeek:id:`Cluster::nodes`.

@load ./main
@load ./pools

module Cluster;

event zeek_init() &priority=-5
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
	}
