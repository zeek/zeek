# $Id: site.bro 416 2004-09-17 03:52:28Z vern $
#
# Definitions describing a site - which networks are "local"
# and "neighbors", and servers running particular services.

# Networks that are considered "local".
const local_nets: set[subnet] &redef;

# Networks that are considered "neighbors".
const neighbor_nets: set[subnet] &redef;

# Function that returns true if an address corresponds to one of
# the local networks, false if not.
function is_local_addr(a: addr): bool
	{
	return a in local_nets;
	}
