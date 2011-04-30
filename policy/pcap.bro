# $Id: pcap.bro 261 2004-08-31 19:25:40Z vern $

# The set of capture_filters indexed by some user-definable ID.
global capture_filters: table[string] of string &redef;
global restrict_filters: table[string] of string &redef;

# By default, Bro will examine all packets. If this is set to false,
# it will dynamically build a BPF filter that only select protocols
# for which the user has loaded a corresponding analysis script.
# The latter used to be default for Bro versions < 1.6. That has now
# changed however to enable port-independent protocol analysis.
const all_packets = T &redef;

# Filter string which is unconditionally or'ed to every dynamically
# built pcap filter.
const unrestricted_filter = "" &redef;

redef enum PcapFilterID += {
	DefaultPcapFilter,
};

function add_to_pcap_filter(fold: string, fnew: string, op: string): string
	{
	if ( fold == "" )
		return fnew;
	else if ( fnew == "" )
		return fold;
	else
		return fmt("(%s) %s (%s)", fold, op, fnew);
	}

function join_filters(capture_filter: string, restrict_filter: string): string
	{
	local filter: string;

	if ( capture_filter != "" && restrict_filter != "" )
		filter = fmt( "(%s) and (%s)", restrict_filter, capture_filter );

	else if ( capture_filter != "" )
		filter = capture_filter;

	else if ( restrict_filter != "" )
		filter = restrict_filter;

	else
		filter = "ip or not ip";

	if ( unrestricted_filter != "" )
		filter = fmt( "(%s) or (%s)", unrestricted_filter, filter );

	return filter;
	}

function build_default_pcap_filter(): string
	{
	if ( cmd_line_bpf_filter != "" )
		# Return what the user specified on the command line;
		return cmd_line_bpf_filter;

	if ( all_packets )
		# Return an "always true" filter.
		return "ip or not ip";

	## Build filter dynamically.

	# First the capture_filter.
	local cfilter = "";
	for ( id in capture_filters )
		cfilter = add_to_pcap_filter(cfilter, capture_filters[id], "or");

	# Then the restrict_filter.
	local rfilter = "";
	for ( id in restrict_filters )
		rfilter = add_to_pcap_filter(rfilter, restrict_filters[id], "and");

	# Finally, join them.
	local filter = join_filters(cfilter, rfilter);

	return filter;
	}

function install_default_pcap_filter()
	{
	if ( ! install_pcap_filter(DefaultPcapFilter) )
		 {
		 ### This could be due to a true failure, or simply
		 # because the user specified -f.  Since we currently
		 # don't have an easy way to distinguish, we punt on
		 # reporting it for now.
		 }
	}

global default_pcap_filter = "<not set>";

function update_default_pcap_filter()
	{
	default_pcap_filter = build_default_pcap_filter();

	if ( ! precompile_pcap_filter(DefaultPcapFilter, default_pcap_filter) )
		 {
		 print fmt("can't compile filter %s", default_pcap_filter);
		 exit();
		 }

	install_default_pcap_filter();
	}

event bro_init()
	{
	update_default_pcap_filter();
	}
