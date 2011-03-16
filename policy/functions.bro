@load site
@load logging

# Some enums for deciding what and when to log.
type Directions_and_Hosts: enum {
	Inbound, Outbound,
	LocalHosts, RemoteHosts,
	Enabled, Disabled
};
const DIRECTIONS = set(Inbound, Outbound, Enabled, Disabled);
const HOSTS = set(LocalHosts, RemoteHosts, Enabled, Disabled);

function id_matches_directions(id: conn_id, d: Directions_and_Hosts): bool
	{
	if ( d == Disabled ) return F;

	return ( d == Enabled ||
	        (d == Outbound && is_local_addr(id$orig_h)) ||
	        (d == Inbound && is_local_addr(id$resp_h)) );
	}
	
function addr_matches_hosts(ip: addr, h: Directions_and_Hosts): bool
	{
	if ( h == Disabled ) return F;
	
	return ( h == Enabled ||
	        (h == LocalHosts && is_local_addr(ip)) ||
	        (h == RemoteHosts && !is_local_addr(ip)) );
	}
