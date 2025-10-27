module XDP::ShuntIPPair;

export {
	## Event raised whenever a connection is shunted.
	global shunted_pair: event(ip1: addr, ip2: addr);

	## Event raised whenever a connection is unshunted.
	global unshunted_pair: event(ip1: addr, ip2: addr, stats: XDP::ShuntedStats);

	## Retrieves the current values in the IP pair map. The parameters are
	## extra filtering before converting into script values. If both are provided,
	## they must both match to include the shunted pair.
	##
	## only_fin: True if filtering for packets with a fin/rst
	##
	## time_since_last_packet: Interval that must elapse since the last packet
	## to include
	##
	## Returns: A table of the IP pairs getting shunted
	global get_map: function(xdp_prog: opaque of XDP::Program, only_fin: bool
	    &default=T, time_since_last_packet: interval &default=0sec)
	    : XDP::shunt_table;

	## Starts shunting anything between two IPs.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: unshunt shunt_stats
	global shunt: function(xdp_prog: opaque of XDP::Program, ip1_val: addr,
	    ip2_val: addr): bool;

	## Provides the shunting statistics for this IP pair.
	##
	## Returns: The shunting statistics
	##
	## .. zeek:see:: shunt unshunt
	global shunt_stats: function(xdp_prog: opaque of XDP::Program, orig_h: addr,
	    resp_h: addr): XDP::ShuntedStats;

	## Stops shunting anything between two IPs.
	##
	## Returns: The shunted statistics right before removing
	##
	## .. zeek:see:: shunt shunt_stats
	global unshunt: function(xdp_prog: opaque of XDP::Program, ip1_val: addr,
	    ip2_val: addr): XDP::ShuntedStats;
}

function get_map(xdp_prog: opaque of XDP::Program, only_fin: bool &default=T,
    time_since_last_packet: interval &default=0sec): XDP::shunt_table
	{
	return _get_map(xdp_prog, only_fin, time_since_last_packet);
	}

function shunt(xdp_prog: opaque of XDP::Program, ip1_val: addr, ip2_val: addr)
    : bool
	{
	local result = _shunt(xdp_prog, ip1_val, ip2_val);
	if ( result )
		event shunted_pair(ip1_val, ip2_val);

	return result;
	}

function shunt_stats(xdp_prog: opaque of XDP::Program, orig_h: addr,
    resp_h: addr): XDP::ShuntedStats
	{
	return _shunt_stats(xdp_prog, orig_h, resp_h);
	}

function unshunt(xdp_prog: opaque of XDP::Program, ip1_val: addr, ip2_val: addr)
    : XDP::ShuntedStats
	{
	local stats = _unshunt(xdp_prog, ip1_val, ip2_val);
	if ( stats$present )
		event unshunted_pair(ip1_val, ip2_val, stats);

	return stats;
	}
