##! This script implements the "Bro side" of several load balancing
##! approaches for Bro clusters.

@load base/frameworks/cluster
@load base/frameworks/packet-filter

module LoadBalancing;

export {

	type Method: enum {
		## Apply BPF filters to each worker in a way that causes them to
		## automatically flow balance traffic between them.
		AUTO_BPF,
		# Load balance traffic across the workers by making each one apply
		# a restrict filter to only listen to a single MAC address.  This
		# is a somewhat common deployment option for sites doing network
		# based load balancing with MAC address rewriting and passing the
		# traffic to a single interface.  Multiple MAC addresses will show
		# up on the same interface and need filtered to a single address.
		#MAC_ADDR_BPF,
	};

	## Defines the method of load balancing to use.
	const method = AUTO_BPF &redef;

	# Configure the cluster framework to enable the load balancing filter configuration.
	#global send_filter: event(for_node: string, filter: string);
	#global confirm_filter_installation: event(success: bool);

	redef record Cluster::Node += {
		## A BPF filter for load balancing traffic sniffed on a single
		## interface across a number of processes.  In normal uses, this
		## will be assigned dynamically by the manager and installed by
		## the workers.
		lb_filter: string &optional;
	};
}

#redef Cluster::manager2worker_events += /LoadBalancing::send_filter/;
#redef Cluster::worker2manager_events += /LoadBalancing::confirm_filter_installation/;

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )

event bro_init() &priority=5
	{
	if ( method != AUTO_BPF )
		return;

	local worker_ip_interface: table[addr, string] of count = table();
	for ( n in Cluster::nodes )
		{
		local this_node = Cluster::nodes[n];

		# Only workers!
		if ( this_node$node_type != Cluster::WORKER ||
		     ! this_node?$interface )
			next;

		if ( [this_node$ip, this_node$interface] !in worker_ip_interface )
			worker_ip_interface[this_node$ip, this_node$interface] = 0;
		++worker_ip_interface[this_node$ip, this_node$interface];
		}

	# Now that we've counted up how many processes are running on an interface
	# let's create the filters for each worker.
	local lb_proc_track: table[addr, string] of count = table();
	for ( no in Cluster::nodes )
		{
		local that_node = Cluster::nodes[no];
		if ( that_node$node_type == Cluster::WORKER &&
		     that_node?$interface && [that_node$ip, that_node$interface] in worker_ip_interface )
			{
			if ( [that_node$ip, that_node$interface] !in lb_proc_track )
				lb_proc_track[that_node$ip, that_node$interface] = 0;

			local this_lb_proc = lb_proc_track[that_node$ip, that_node$interface];
			local total_lb_procs = worker_ip_interface[that_node$ip, that_node$interface];

			++lb_proc_track[that_node$ip, that_node$interface];
			if ( total_lb_procs > 1 )
				{
				that_node$lb_filter = PacketFilter::sample_filter(total_lb_procs, this_lb_proc);
				Communication::nodes[no]$capture_filter = that_node$lb_filter;
				}
			}
		}
	}

#event remote_connection_established(p: event_peer) &priority=-5
#	{
#	if ( is_remote_event() )
#		return;
#
#	local for_node = p$descr;
#	# Send the filter to the peer.
#	if ( for_node in Cluster::nodes &&
#	     Cluster::nodes[for_node]?$lb_filter )
#		{
#		local filter = Cluster::nodes[for_node]$lb_filter;
#		event LoadBalancing::send_filter(for_node, filter);
#		}
#	}

#event LoadBalancing::confirm_filter_installation(success: bool)
#	{
#	# This doesn't really matter yet since we aren't getting back a meaningful success response.
#	}

@endif


@if ( Cluster::local_node_type() == Cluster::WORKER )

#event LoadBalancing::send_filter(for_node: string, filter: string)
event remote_capture_filter(p: event_peer, filter: string)
	{
	#if ( for_node !in Cluster::nodes )
	#	return;
	#
	#if ( Cluster::node == for_node )
	#	{
		restrict_filters["lb_filter"] = filter;
		PacketFilter::install();
		#event LoadBalancing::confirm_filter_installation(T);
	#	}
	}

@endif

@endif
