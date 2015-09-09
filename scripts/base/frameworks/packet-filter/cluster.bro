
@load base/frameworks/cluster
@load ./main

module PacketFilter;

event remote_connection_handshake_done(p: event_peer) &priority=3
	{
	if ( Cluster::local_node_type() == Cluster::WORKER && 
	     p$descr in Cluster::nodes && 
	     Cluster::nodes[p$descr]$node_type == Cluster::MANAGER )
		{
		# This ensures that a packet filter is installed and logged
		# after the manager connects to us.
		install();
		}
	}
