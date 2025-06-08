##! Cluster-related functionality specific to running under the Supervisor
##! framework.

@load base/frameworks/supervisor/api

module Cluster::Supervisor;

export {
	## Populates the current node's :zeek:id:`Cluster::nodes` table from the
	## supervisor's node configuration in :zeek:id:`Supervisor::NodeConfig`.
	##
	## Returns: true if initialization completed, false otherwise.
	global __init_cluster_nodes: function(): bool;
}

function __init_cluster_nodes(): bool
	{
	local config = Supervisor::node();

	if ( |config$cluster| == 0 )
		return F;

	local rolemap: table[Supervisor::ClusterRole] of Cluster::NodeType = {
		[Supervisor::LOGGER] = Cluster::LOGGER,
		[Supervisor::MANAGER] = Cluster::MANAGER,
		[Supervisor::PROXY] = Cluster::PROXY,
		[Supervisor::WORKER] = Cluster::WORKER,
	};

	local manager_name = "";
	local cnode: Cluster::Node;
	local typ: Cluster::NodeType = Cluster::NONE;

	for ( node_name, endp in config$cluster )
		{
		if ( endp$role == Supervisor::MANAGER )
			manager_name = node_name;
		}

	for ( node_name, endp in config$cluster )
		{
		if ( endp$role in rolemap )
			typ = rolemap[endp$role];

		cnode = Cluster::Node($node_type=typ, $ip=endp$host, $p=endp$p);
		if ( |manager_name| > 0 && cnode$node_type != Cluster::MANAGER )
			cnode$manager = manager_name;
		if ( endp?$metrics_port )
			cnode$metrics_port = endp$metrics_port;

		Cluster::nodes[node_name] = cnode;
		}

	return T;
	}
