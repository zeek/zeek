@load site
@load logging
@load dpd

# TODO: move this somewhere else.  It doesn't seem appropriate here.
const private_address_space: set[subnet] = {10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8, 172.16.0.0/12};

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


# Functions for finding IP addresses in strings, etc.
############# BEGIN IP FUNCTIONS #############
# Regular expressions for matching IP addresses in strings.
const ipv4_addr_regex = /[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}/;
const ipv6_8hex_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/;
const ipv6_compressed_hex_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/;
const ipv6_hex4dec_regex = /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;
const ipv6_compressed_hex4dec_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;

# These are commented out until I construct patterns this way at init time.
#const ipv6_addr_regex = ipv6_8hex_regex |
#                        ipv6_compressed_hex_regex |
#                        ipv6_hex4dec_regex |
#                        ipv6_compressed_hex4dec_regex;
#const ip_addr_regex = ipv4_addr_regex | ipv6_addr_regex;

const ipv6_addr_regex =     
    /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/ |
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/ | # IPv6 Compressed Hex
    /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/ | # 6Hex4Dec
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/; # CompressedHex4Dec

const ip_addr_regex = 
    /[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}/ |
    /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/ |
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/ | # IPv6 Compressed Hex
    /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/ | # 6Hex4Dec
    /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/; # CompressedHex4Dec

function is_valid_ip(ip_str: string): bool
	{
	if ( ip_str == ipv4_addr_regex )
		{
		local octets = split(ip_str, /\./);
		if ( |octets| != 4 )
			return F;
		
		local num=0;
		for ( i in octets )
			{
			num = to_count(octets[i]);
			if ( num < 0 || 255 < num )
				return F;
			}
		return T;
		}
	else if ( ip_str == ipv6_addr_regex )
		{
		# TODO: make this work correctly.
		return T;
		}
	return F;
	}

# This outputs a string_array of ip addresses extracted from a string.
# given: "this is 1.1.1.1 a test 2.2.2.2 string with ip addresses 3.3.3.3"
# outputs: { [1] = 1.1.1.1, [2] = 2.2.2.2, [3] = 3.3.3.3 }
function find_ip_addresses(input: string): string_array
	{
	local parts = split_all(input, ip_addr_regex);
	local output: string_array;

	for ( i in parts )
		{
		if ( i % 2 == 0 && is_valid_ip(parts[i]) )
			output[|output|+1] = parts[i];
		}
	return output;
	}
############# END IP FUNCTIONS #############



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
