@load site
@load logging

# Simple functions for generating ASCII connection identifiers.
############# BEGIN ID FORMATTING #############
function id_string(id: conn_id): string
	{
	return fmt("%s %d > %s %d",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function reverse_id_string(id: conn_id): string
	{
	return fmt("%s %d < %s %d",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function directed_id_string(id: conn_id, is_orig: bool): string
	{
	return is_orig ? id_string(id) : reverse_id_string(id);
	}
############# END ID FORMATTING #############



############# BEGIN THRESHOLD CHECKING #############
type track_count: record {
	n: count &default=0;
	index: count &default=0;
};

function default_track_count(a: addr): track_count
	{
	local x: track_count;
	return x;
	}

const default_notice_thresholds: vector of count = {
	30, 100, 1000, 10000, 100000, 1000000, 10000000,
} &redef;

# This is total rip off from scan.bro, but placed in the global namespace
# and slightly reworked to be easier to work with and more general.
function check_threshold(v: vector of count, tracker: track_count): bool
	{
	if ( tracker$index <= |v| && tracker$n >= v[tracker$index] )
		{
		++tracker$index;
		return T;
		}
	return F;
	}

function default_check_threshold(tracker: track_count): bool
	{
	return check_threshold(default_notice_thresholds, tracker);
	}
############# END THRESHOLD CHECKING #############


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
