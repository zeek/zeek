##! Definitions describing a site - which networks and DNS zones are "local"
##! and "neighbors", and servers running particular services.
@load utils/pattern

# Networks that are considered "local".
const local_nets: set[subnet] &redef;

# Networks that are considered "neighbors".
const neighbor_nets: set[subnet] &redef;

# DNS zones that are considered "local".
const local_zones: set[string] &redef;

# DNS zones that are considered "neighbors".
const neighbor_zones: set[string] &redef;

# This is an interally used variable.
global local_dns_suffix_regex: pattern = /MATCH_NOTHING!/;


# Function that returns true if an address corresponds to one of
# the local networks, false if not.
function is_local_addr(a: addr): bool
	{
	return a in local_nets;
	}
	
function is_local_name(name: string): bool
	{
	return local_dns_suffix_regex in name;
	}

event bro_init() &priority=10
	{
	# Double backslashes are needed due to string parsing.
	local_dns_suffix_regex = set_to_regex(local_zones, "(^\\.?|\\.)(~~)$");
	}
