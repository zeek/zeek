module PacketFilter;

export {
	## Takes a :bro:type:`port` and returns a BPF expression which will
	## match the port.
	##
	## p: The port.
	##
	## Returns: A valid BPF filter string for matching the port.
	global port_to_bpf: function(p: port): string;

	## Create a BPF filter to sample IPv4 and IPv6 traffic.
	##
	## num_parts: The number of parts the traffic should be split into.
	##
	## this_part: The part of the traffic this filter will accept (0-based).
	global sampling_filter: function(num_parts: count, this_part: count): string;

	## Combines two valid BPF filter strings with a string based operator
	## to form a new filter.
	##
	## lfilter: Filter which will go on the left side.
	##
	## op: Operation being applied (typically "or" or "and").
	##
	## rfilter: Filter which will go on the right side.
	##
	## Returns: A new string representing the two filters combined with
	##          the operator.  Either filter being an empty string will
	##          still result in a valid filter.
	global combine_filters: function(lfilter: string, op: string, rfilter: string): string;
}

function port_to_bpf(p: port): string
	{
	local tp = get_port_transport_proto(p);
	return cat(tp, " and ", fmt("port %d", p));
	}

function combine_filters(lfilter: string,  op: string, rfilter: string): string
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

function sampling_filter(num_parts: count, this_part: count): string
	{
	local v4_filter = fmt("ip and ((ip[14:2]+ip[18:2]) - (%d*((ip[14:2]+ip[18:2])/%d)) == %d)", num_parts, num_parts, this_part);
	# TODO: this is probably a fairly suboptimal filter, but it should work for now.
	local v6_filter = fmt("ip6 and ((ip6[22:2]+ip6[38:2]) - (%d*((ip6[22:2]+ip6[38:2])/%d)) == %d)", num_parts, num_parts, this_part);
	return combine_filters(v4_filter, "or", v6_filter);
	}
