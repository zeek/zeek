module PacketFilter;

export {
	## Takes a :bro:type:`port` and returns a BPF expression which will
	## match the port.
	##
	## p: The port.
	##
	## Returns: A valid BPF filter string for matching the port.
	global port_to_bpf: function(p: port): string;
	
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