##! This script supports how Bro sets it's BPF capture filter.  By default
##! Bro sets an unrestricted filter that allows all traffic.  If a filter
##! is set on the command line, that filter takes precedence over the default
##! open filter and all filter defined internally in Bro scripts.

module Filter;

export {
	redef enum PcapFilterID += {
		DefaultPcapFilter,
	};

	## By default, Bro will examine all packets. If this is set to false,
	## it will dynamically build a BPF filter that only select protocols
	## for which the user has loaded a corresponding analysis script.
	## The latter used to be default for Bro versions < 1.6. That has now
	## changed however to enable port-independent protocol analysis.
	const all_packets = T &redef;
	
	# Filter string which is unconditionally or'ed to every dynamically
	# built pcap filter.
	const unrestricted_filter = "" &redef;
}

global default_pcap_filter = "<not set yet>";

function combine_filters(lfilter: string, rfilter: string, op: string): string
	{
	if ( lfilter == "" && rfilter == "" )
		return "";
	else if ( lfilter == "" )
		return rfilter;
	else if ( rfilter == "" )
		return lfilter;
	else
		return fmt("(%s) %s (%s)", lfilter, op, rfilter);
	}

function build_default_filter(): string
	{
	if ( cmd_line_bpf_filter != "" )
		# Return what the user specified on the command line;
		return cmd_line_bpf_filter;

	if ( all_packets )
		{
		# Return an "always true" filter.
		if ( bro_has_ipv6() )
			return "ip or not ip";
		else
			return "not ip6";
		}

	# Build filter dynamically.
	
	# First the capture_filter.
	local cfilter = "";
	for ( id in capture_filters )
		cfilter = combine_filters(cfilter, capture_filters[id], "or");
		
	# Then the restrict_filter.
	local rfilter = "";
	for ( id in restrict_filters )
		rfilter = combine_filters(rfilter, restrict_filters[id], "and");
		
	# Finally, join them into one filter.
	local filter = combine_filters(rfilter, cfilter, "and");
	if ( unrestricted_filter != "" )
		filter = combine_filters(unrestricted_filter, filter, "or");
	
	# Exclude IPv6 if we don't support it.
	if ( ! bro_has_ipv6() )
		filter = combine_filters(filter, "not ip6", "and");
	
	return filter;
	}

function install_default_pcap_filter()
	{
	if ( ! install_pcap_filter(DefaultPcapFilter) )
		{
		# This could be due to a true failure, or simply
		# because the user specified -f.  Since we currently
		# don't have an easy way to distinguish, we punt on
		# reporting it for now.
		}
	}

function update_default_pcap_filter()
	{
	default_pcap_filter = build_default_filter();

	if ( ! precompile_pcap_filter(DefaultPcapFilter, default_pcap_filter) )
		{
		print fmt("can't compile filter %s", default_pcap_filter);
		exit();
		}

	install_default_pcap_filter();
	}

event bro_init() &priority=10
	{
	update_default_pcap_filter();
	}
