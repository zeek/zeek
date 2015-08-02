
@load base/frameworks/cluster
@load ./main

module PacketFilter;

event remote_connection_handshake_done(p: event_peer) &priority=3
	{
	if ( Cluster::has_local_role(Cluster::WORKER) && 
	     p$descr in Cluster::nodes && 
	     Cluster::MANAGER in Cluster::nodes[p$descr]$node_roles  )
		{
		# This ensures that a packet filter is installed and logged
		# after the manager connects to us.
		install();
		}
	}
