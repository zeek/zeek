##! This script supports how Bro sets it's BPF capture filter.  By default
##! Bro sets an unrestricted filter that allows all traffic.  If a filter
##! is set on the command line, that filter takes precedence over the default
##! open filter and all filters defined in Bro scripts with the
##! :bro:id:`capture_filters` and :bro:id:`restrict_filters` variables.

@load base/frameworks/notice

module PacketFilter;

export {
	## Add the packet filter logging stream.
	redef enum Log::ID += { LOG };

	## Add notice types related to packet filter errors.
	redef enum Notice::Type += {
		## This notice is generated if a packet filter is unable to be compiled.
		Compile_Failure,

		## This notice is generated if a packet filter is fails to install.
		Install_Failure,
	};

	## The record type defining columns to be logged in the packet filter
	## logging stream.
	type Info: record {
		## The time at which the packet filter installation attempt was made.
		ts:     time   &log;

		## This is a string representation of the node that applied this
		## packet filter.  It's mostly useful in the context of dynamically
		## changing filters on clusters.
		node:   string &log &optional;

		## The packet filter that is being set.
		filter: string &log;

		## Indicate if this is the filter set during initialization.
		init:   bool   &log &default=F;

		## Indicate if the filter was applied successfully.
		success: bool  &log &default=T;
	};

	## By default, Bro will examine all packets. If this is set to false,
	## it will dynamically build a BPF filter that only select protocols
	## for which the user has loaded a corresponding analysis script.
	## The latter used to be default for Bro versions < 2.0. That has now
	## changed however to enable port-independent protocol analysis.
	const all_packets = T &redef;

	## Filter string which is unconditionally or'ed to the beginning of every
	## dynamically built filter.
	const unrestricted_filter = "" &redef;

	## Call this function to build and install a new dynamically built
	## packet filter.
	global install: function();

	## This is where the default packet filter is stored and it should not
	## normally be modified by users.
	global default_filter = "<not set yet>";
}

redef enum PcapFilterID += {
	DefaultPcapFilter,
};

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
		# Return an "always true" filter.
		return "ip or not ip";

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

	return filter;
	}

function install()
	{
	default_filter = build_default_filter();

	if ( ! precompile_pcap_filter(DefaultPcapFilter, default_filter) )
		{
		NOTICE([$note=Compile_Failure,
		        $msg=fmt("Compiling packet filter failed"),
		        $sub=default_filter]);
		Reporter::fatal(fmt("Bad pcap filter '%s'", default_filter));
		}

	# Do an audit log for the packet filter.
	local info: Info;
	info$ts = network_time();
	# If network_time() is 0.0 we're at init time so use the wall clock.
	if ( info$ts == 0.0 )
		{
		info$ts = current_time();
		info$init = T;
		}
	info$filter = default_filter;

	if ( ! install_pcap_filter(DefaultPcapFilter) )
		{
		# Installing the filter failed for some reason.
		info$success = F;
		NOTICE([$note=Install_Failure,
		        $msg=fmt("Installing packet filter failed"),
		        $sub=default_filter]);
		}

	if ( reading_live_traffic() || reading_traces() )
		Log::write(PacketFilter::LOG, info);
	}

event bro_init() &priority=10
	{
	Log::create_stream(PacketFilter::LOG, [$columns=Info]);
	PacketFilter::install();
	}
