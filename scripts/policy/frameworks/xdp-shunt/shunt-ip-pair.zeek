##! Shunting pairs of IP addresses. This form of shunting is more
##! static, so no functionality is in place to unshunt the connections.
@ifdef ( XDP::__load_and_attach )
module XDP::Shunt::IPPair;

@load ./main

export {
	## Event raised whenever a connection is shunted.
	global shunted_pair: event(pair: XDP::ip_pair);

	## Event raised whenever a connection is unshunted.
	global unshunted_pair: event(pair: XDP::ip_pair, stats: XDP::ShuntedStats);

	## Retrieves the current values in the IP pair map.
	##
	## time_since_last_packet: Interval that must elapse since the last packet
	## to include
	##
	## Returns: A table of the IP pairs getting shunted
	global get_map: function(time_since_last_packet: interval &default=0sec)
	    : XDP::shunt_table;

	## Starts shunting anything between two IPs.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: unshunt shunt_stats
	global shunt: function(pair: XDP::ip_pair): bool;

	## Provides the shunting statistics for this IP pair.
	##
	## Returns: The shunting statistics
	##
	## .. zeek:see:: shunt unshunt
	global shunt_stats: function(pair: XDP::ip_pair): XDP::ShuntedStats;

	## Stops shunting anything between two IPs.
	##
	## Returns: The shunted statistics right before removing
	##
	## .. zeek:see:: shunt shunt_stats
	global unshunt: function(pair: XDP::ip_pair): XDP::ShuntedStats;
}

function get_map(time_since_last_packet: interval &default=0sec)
    : XDP::shunt_table
	{
	return __get_map(XDP::xdp_prog, time_since_last_packet);
	}

function shunt(pair: XDP::ip_pair): bool
	{
	local result = __shunt(XDP::xdp_prog, pair);
	if ( result )
		event shunted_pair(pair);

	return result;
	}

function shunt_stats(pair: XDP::ip_pair): XDP::ShuntedStats
	{
	return __shunt_stats(XDP::xdp_prog, pair);
	}

function unshunt(pair: XDP::ip_pair): XDP::ShuntedStats
	{
	local stats = __unshunt(XDP::xdp_prog, pair);
	if ( stats$present )
		event unshunted_pair(pair, stats);

	return stats;
	}

@endif
