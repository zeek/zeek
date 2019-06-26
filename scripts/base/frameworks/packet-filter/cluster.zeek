
@load base/frameworks/cluster
@load ./main

module PacketFilter;

event Cluster::hello(name: string, id: string) &priority=-3
	{
	if ( Cluster::local_node_type() == Cluster::WORKER &&
	     name in Cluster::nodes &&
	     Cluster::nodes[name]$node_type == Cluster::MANAGER )
		{
		# This ensures that a packet filter is installed and logged
		# after the manager connects to us.
		install();
		}
	}
