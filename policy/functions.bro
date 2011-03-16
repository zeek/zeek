@load site
@load logging
@load dpd

# Returns true if the given string is at least 25% composed of 8-bit
# characters.
function is_string_binary(s: string): bool
	{
	return byte_len(gsub(s, /[\x00-\x7f]/, "")) * 100 / |s| >= 25;
	}

# Given an arbitrary string, this should extract a single directory.
# TODO: Make this work on Window's style directories.
# NOTE: This does nothing to remove a filename if that's included.
function extract_directory(input: string): string
	{
	const dir_pattern = /\"([^\"]|\"\")*(\/|\\)([^\"]|\"\")*\"/;
	local parts = split_all(input, dir_pattern);

	# This basically indicates no identifiable directory was found.
	if ( |parts| < 3 )
		return "";

	local d = parts[2];
	return sub_bytes(d, 2, int_to_count(|d| - 2));
	}

# Process ..'s and eliminate duplicate '/'s
# Deficiency: gives wrong results when a symbolic link is followed by ".."
function compress_path(dir: string): string
	{
	const cdup_sep = /((\/)+([^\/]|\\\/)+)?((\/)+\.\.(\/)+)/;

	local parts = split_n(dir, cdup_sep, T, 1);
	if ( length(parts) > 1 )
		{
		parts[2] = "/";
		dir = cat_string_array(parts);
		return compress_path(dir);
		}

	const multislash_sep = /(\/){2,}/;
	parts = split_all(dir, multislash_sep);
	for ( i in parts )
		if ( i % 2 == 0 )
			parts[i] = "/";
	dir = cat_string_array(parts);

	return dir;
	}

const absolute_path_pat = /(\/|[A-Za-z]:[\\\/]).*/;
# Computes the absolute path with cwd (current working directory).
function absolute_path(cwd: string, file_name: string): string
	{
	local abs_file_name: string;
	if ( file_name == absolute_path_pat ) # start with '/' or 'A:\'
		abs_file_name = file_name;
	else
		abs_file_name = string_cat(cwd, "/", file_name);
	return compress_path(abs_file_name);
	}

function build_full_path(cwd: string, file_name: string): string
	{
	return (file_name == absolute_path_pat) ?
		file_name : cat(cwd, "/", file_name);
	}

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
type TrackCount: record {
	n: count &default=0;
	index: count &default=0;
};

function default_track_count(a: addr): TrackCount
	{
	local x: TrackCount;
	return x;
	}

const default_notice_thresholds: vector of count = {
	30, 100, 1000, 10000, 100000, 1000000, 10000000,
} &redef;

# This is total rip off from scan.bro, but placed in the global namespace
# and slightly reworked to be easier to work with and more general.
function check_threshold(v: vector of count, tracker: TrackCount): bool
	{
	if ( tracker$index <= |v| && tracker$n >= v[tracker$index] )
		{
		++tracker$index;
		return T;
		}
	return F;
	}

function default_check_threshold(tracker: TrackCount): bool
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
