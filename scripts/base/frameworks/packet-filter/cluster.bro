
@load base/frameworks/cluster
@load ./main

module PacketFilter;

event outgoing_connection_established(peer_address: string, peer_port: port,
                                      peer_name: string) &priority=3
	{
	if ( Cluster::has_local_role(Cluster::WORKER) &&
	     peer_name in Cluster::nodes &&
	     Cluster::MANAGER in Cluster::nodes[peer_name]$node_roles )
		{
		# This ensures that a packet filter is installed and logged
		# after we connect to the manager.
		install();
		}
	}
