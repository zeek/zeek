# $Id: pcap.bro 261 2004-08-31 19:25:40Z vern $

# The set of capture_filters indexed by some user-definable ID.
global capture_filters: table[string] of string &redef;
global restrict_filters: table[string] of string &redef;

# Filter string which is unconditionally or'ed to every pcap filter.
global unrestricted_filter = "" &redef;

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
		filter = "tcp or udp or icmp";

	if ( unrestricted_filter != "" )
		filter = fmt( "(%s) or (%s)", unrestricted_filter, filter );

	return filter;
	}

function build_default_pcap_filter(): string
	{
	# Build capture_filter.
	local cfilter = "";

	for ( id in capture_filters )
		cfilter = add_to_pcap_filter(cfilter, capture_filters[id], "or");

	# Build restrict_filter.
	local rfilter = "";
	local saw_VLAN = F;
	for ( id in restrict_filters )
		{
		if ( restrict_filters[id] == "vlan" )
			# These are special - they need to come first.
			saw_VLAN = T;
		else
			rfilter = add_to_pcap_filter(rfilter, restrict_filters[id], "and");
		}

	if ( saw_VLAN )
		rfilter = add_to_pcap_filter("vlan", rfilter, "and");

	return join_filters(cfilter, rfilter);
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
