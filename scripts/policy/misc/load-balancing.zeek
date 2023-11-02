##! This script implements the "Zeek side" of several load balancing
##! approaches for Zeek clusters.

@deprecated "Remove in v7.1. This script has not seen extensions for the past 10 years and is not at all recommended to use for packet load balancing purposes. On Linux, AF_PACKET is recommended and works out of the box. On FreeBSD, there is Netmap with lb. Otherwise, NIC specific packet sources and approaches exist that handle the load balancing."

@pragma push ignore-deprecations

@load base/frameworks/cluster
@load base/frameworks/packet-filter

module LoadBalancing;

export {

	type Method: enum {
		## Apply BPF filters to each worker in a way that causes them to
		## automatically flow balance traffic between them.
		AUTO_BPF,
	};

	## Defines the method of load balancing to use.
	const method = AUTO_BPF &redef;

	redef record Cluster::Node += {
		## A BPF filter for load balancing traffic sniffed on a single
		## interface across a number of processes.  In normal uses, this
		## will be assigned dynamically by the manager and installed by
		## the workers.
		lb_filter: string &optional;
	};
}

@if ( Cluster::is_enabled() )

event zeek_init() &priority=5
	{
	if ( method != AUTO_BPF )
		return;

	local worker_ip_interface: table[addr, string] of count = table();
	local sorted_node_names: vector of string = vector();
	local node: Cluster::Node;
	local name: string;

	# Sort nodes list so that every node iterates over it in same order.
	for ( name in Cluster::nodes )
		sorted_node_names += name;

	sort(sorted_node_names, strcmp);

	for ( idx in sorted_node_names )
		{
		name = sorted_node_names[idx];
		node = Cluster::nodes[name];

		if ( node$node_type != Cluster::WORKER )
			next;

		if ( ! node?$interface )
			next;

		if ( [node$ip, node$interface] !in worker_ip_interface )
			worker_ip_interface[node$ip, node$interface] = 0;

		++worker_ip_interface[node$ip, node$interface];
		}

	# Now that we've counted up how many processes are running per
	# interface, let's create the filters for each worker.
	local lb_proc_track: table[addr, string] of count = table();

	for ( idx in sorted_node_names )
		{
		name = sorted_node_names[idx];
		node = Cluster::nodes[name];

		if ( node$node_type != Cluster::WORKER )
			next;

		if ( ! node?$interface )
			next;

		if ( [node$ip, node$interface] !in worker_ip_interface )
			next;

		if ( [node$ip, node$interface] !in lb_proc_track )
			lb_proc_track[node$ip, node$interface] = 0;

		local this_lb_proc = lb_proc_track[node$ip, node$interface];
		local total_lb_procs = worker_ip_interface[node$ip, node$interface];
		++lb_proc_track[node$ip, node$interface];

		if ( total_lb_procs > 1 )
			node$lb_filter = PacketFilter::sampling_filter(total_lb_procs,
			                                               this_lb_proc);
		}

	# Finally, install filter for the current node if it needs one.
	for ( idx in sorted_node_names )
		{
		name = sorted_node_names[idx];
		node = Cluster::nodes[name];

		if ( name != Cluster::node )
			next;

		if ( ! node?$lb_filter )
			next;

		restrict_filters["lb_filter"] = node$lb_filter;
		PacketFilter::install();
		}
	}

@endif

@pragma pop
