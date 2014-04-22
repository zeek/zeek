@load ./site

type Direction: enum {
	## The connection originator is not within the locally-monitored
	## network, but the other endpoint is.
	INBOUND,
	## The connection originator is within the locally-monitored network,
	## but the other endpoint is not.
	OUTBOUND,
	## Only one endpoint is within the locally-monitored network, meaning
	## the connection is either outbound or inbound.
	BIDIRECTIONAL,
	## This value doesn't match any connection.
	NO_DIRECTION
};

## Checks whether a given connection is of a given direction with respect
## to the locally-monitored network.
##
## id: a connection record containing the originator/responder hosts.
##
## d: a direction with respect to the locally-monitored network.
##
## Returns: T if the two connection endpoints match the given direction, else F.
function id_matches_direction(id: conn_id, d: Direction): bool
	{
	if ( d == NO_DIRECTION ) return F;

	local o_local = Site::is_local_addr(id$orig_h);
	local r_local = Site::is_local_addr(id$resp_h);

	if ( d == BIDIRECTIONAL )
		return (o_local && !r_local) || (!o_local && r_local);
	else if ( d == OUTBOUND )
		return o_local && !r_local;
	else if ( d == INBOUND )
		return !o_local && r_local;
	}

type Host: enum {
	## A host within the locally-monitored network.
	LOCAL_HOSTS,
	## A host not within the locally-monitored network.
	REMOTE_HOSTS,
	## Any host.
	ALL_HOSTS,
	## This value doesn't match any host.
	NO_HOSTS
};

## Checks whether a given host (IP address) matches a given host type.
##
## ip: address of a host.
##
## h: a host type.
##
## Returns: T if the given host matches the given type, else F.
function addr_matches_host(ip: addr, h: Host): bool
	{
	if ( h == NO_HOSTS ) return F;
	
	return ( h == ALL_HOSTS ||
	        (h == LOCAL_HOSTS && Site::is_local_addr(ip)) ||
	        (h == REMOTE_HOSTS && !Site::is_local_addr(ip)) );
	}
