@load site

type Direction: enum { INBOUND, OUTBOUND, BIDIRECTIONAL, NO_DIRECTION };
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
	
type Host: enum { LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS };
function addr_matches_host(ip: addr, h: Host): bool
	{
	if ( h == NO_HOSTS ) return F;
	
	return ( h == ALL_HOSTS ||
	        (h == LOCAL_HOSTS && Site::is_local_addr(ip)) ||
	        (h == REMOTE_HOSTS && !Site::is_local_addr(ip)) );
	}
