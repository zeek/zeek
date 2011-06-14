type Direction: enum { INBOUND, OUTBOUND, BIDIRECTIONAL, NO_DIRECTION };
function id_matches_directions(id: conn_id, d: Direction): bool
	{
	if ( d == NO_DIRECTION ) return F;

	return ( d == BIDIRECTIONAL ||
	        (d == OUTBOUND && is_local_addr(id$orig_h)) ||
	        (d == INBOUND && is_local_addr(id$resp_h)) );
	}
	
type Host: enum { LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS };
function addr_matches_hosts(ip: addr, h: Host): bool
	{
	if ( h == NO_HOSTS ) return F;
	
	return ( h == ALL_HOSTS ||
	        (h == LOCAL_HOSTS && is_local_addr(ip)) ||
	        (h == REMOTE_HOSTS && !is_local_addr(ip)) );
	}
