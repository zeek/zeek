##! Definitions describing a site - which networks and DNS zones are "local"
##! and "neighbors", and servers running particular services.
@load utils/pattern

module GLOBAL;

export {
	## Address space that is considered private and unrouted.
	## By default it has RFC defined non-routable IPv4 address space.
	const private_address_space: set[subnet] = {
		10.0.0.0/8, 
		192.168.0.0/16, 
		127.0.0.0/8, 
		172.16.0.0/12
	} &redef;

	## Networks that are considered "local".
	const local_nets: set[subnet] &redef;

	## Networks that are considered "neighbors".
	const neighbor_nets: set[subnet] &redef;

	## DNS zones that are considered "local".
	const local_zones: set[string] &redef;

	## DNS zones that are considered "neighbors".
	const neighbor_zones: set[string] &redef;

	## Function that returns true if an address corresponds to one of
	## the local networks, false if not.
	global is_local_addr: function(a: addr): bool;
	
	## Function that returns true if an address corresponds to one of
	## the neighbor networks, false if not.
	global is_neighbor_addr: function(a: addr): bool;

	## Function that returns true if a host name is within a local 
	## DNS zone.
	global is_local_name: function(name: string): bool;
	
	## Function that returns true if a host name is within a neighbor 
	## DNS zone.
	global is_neighbor_name: function(name: string): bool;
	
}

# Please ignore, this is an interally used variable.
global local_dns_suffix_regex: pattern = /MATCH_NOTHING/;
global local_dns_neighbor_suffix_regex: pattern = /MATCH_NOTHING/;


function is_local_addr(a: addr): bool
	{
	return a in local_nets;
	}
	
function is_neighbor_addr(a: addr): bool
	{
	return a in neighbor_nets;
	}
	
function is_private_addr(a: addr): bool
	{
	return a in private_address_space;
	}
	
function is_local_name(name: string): bool
	{
	return local_dns_suffix_regex in name;
	}
	
function is_neighbor_name(name: string): bool
	{
	return local_dns_neighbor_suffix_regex in name;
	}

event bro_init() &priority=10
	{
	# Double backslashes are needed due to string parsing.
	local_dns_suffix_regex = set_to_regex(local_zones, "(^\\.?|\\.)(~~)$");
	local_dns_neighbor_suffix_regex = set_to_regex(neighbor_zones, "(^\\.?|\\.)(~~)$");
	}
