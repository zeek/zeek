# Some enums for deciding what and when to log.
type DirectionsAndHosts: enum {
	Inbound, Outbound, Bidirectional,
	LocalHosts, RemoteHosts, AllHosts,
	NoHosts, Disabled
};

function id_matches_directions(id: conn_id, d: DirectionsAndHosts): bool
	{
	if ( d == Disabled ) return F;

	return ( d == Bidirectional ||
	        (d == Outbound && is_local_addr(id$orig_h)) ||
	        (d == Inbound && is_local_addr(id$resp_h)) );
	}
	
function addr_matches_hosts(ip: addr, h: DirectionsAndHosts): bool
	{
	if ( h == Disabled || h == NoHosts ) return F;
	
	return ( h == AllHosts ||
	        (h == LocalHosts && is_local_addr(ip)) ||
	        (h == RemoteHosts && !is_local_addr(ip)) );
	}
