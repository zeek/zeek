function numeric_id_string(id: conn_id): string
	{
	return fmt("%s:%d > %s:%d",
	           id$orig_h, id$orig_p,
	           id$resp_h, id$resp_p);
	}

function fmt_addr_set(input: addr_set): string
	{
	local output = "";
	local tmp = "";
	local len = length(input);
	local i = 1;

	for ( item in input )
		{
		tmp = fmt("%s", item);
		if ( len != i )
			tmp = fmt("%s ", tmp);
		i = i+1;
		output = fmt("%s%s", output, tmp);
		}
	return fmt("%s", output);
	}
	
function fmt_str_set(input: string_set, strip: pattern): string
	{
	local len = length(input);
	if ( len == 0 )
		return "{}";
	
	local output = "{";
	local tmp = "";
	local i = 1;
	
	for ( item in input )
		{
		tmp = fmt("%s", gsub(item, strip, ""));
		if ( len != i )
			tmp = fmt("%s, ", tmp);
		i = i+1;
		output = fmt("%s%s", output, tmp);
		}
	return fmt("%s}", output);
	}

# Regular expressions for matching IP addresses in strings.
const ipv4_addr_regex = /[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}/;
const ipv6_8hex_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/;
const ipv6_compressed_hex_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/;
const ipv6_hex4dec_regex = /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;
const ipv6_compressed_hex4dec_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;

# These are only commented out until this bug is fixed:
#    http://www.bro-ids.org/wiki/index.php/Known_Issues#Bug_with_OR-ing_together_pattern_variables
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
	
########################################
# The following functions are for getting contact information (email) for an
# IP address in your organization.  It will return data from nested subnets
# as well.
# Below is an example for using it:
#
#	redef subnet_to_admin_table += {
#		[146.128.0.0/16] = "security@yourorg.com",
#		[146.128.94.0/24] = "someone@yourorg.com",
#	};
#	
#	event bro_init()
#		{
#		print fmt_email_string(find_all_emails(146.128.94.3));
#			=> "security@yourorg.com, someone@yourorg.com"
#		print fmt_email_string(find_all_emails(146.128.3.3));
#			=> "security@yourorg.com"
#		}
########################################
# TODO: make this work with IPv6
function find_all_emails(ip: addr): set[string]
	{
	if ( ip !in subnet_to_admin_table ) return set();

	local output_values: set[string] = set();
	local tmp_ip: addr;
	local i: count;
	local emails: string;
	for ( i in one_to_32 )
		{
		tmp_ip = mask_addr(ip, one_to_32[i]);
		emails = subnet_to_admin_table[tmp_ip];
		if ( emails != "" )
			add output_values[emails];
		}
	return output_values;
	}
	
function fmt_email_string(emails: set[string]): string
	{
	local output="";
	for( email in emails )
		{
		if ( output == "" )
			output = email;
		else
			output = fmt("%s, %s", output, email);
		}
	return output;
	}
	
########################################

# Get a software version instance full of zeros.
function get_default_software_version(): software_version
	{
	local tmp_int: int = 0;
	local tmp_v: software_version = [$major=tmp_int,
	                                 $minor=tmp_int,
	                                 $minor2=tmp_int,
	                                 $addl=""];
	return tmp_v;
	}
	
function default_software_parsing(sw: string): software
	{
	local software_name = "";
	local v = get_default_software_version();

	# The regular expression should match the complete version number
	local version_parts = split_all(sw, /[0-9\-\._]{2,}/);
	if ( |version_parts| >= 2 )
		{
		# Remove the name/version separator
		software_name = sub(version_parts[1], /.$/, "");
		local version_numbers = split_n(version_parts[2], /[\-\._[:blank:]]/, F, 4);
		if ( |version_numbers| >= 4 )
			v$addl = version_numbers[4];
		if ( |version_numbers| >= 3 )
			v$minor2 = to_int(version_numbers[3]);
		if ( |version_numbers| >= 2 )
			v$minor = to_int(version_numbers[2]);
		if ( |version_numbers| >= 1 )
			v$major = to_int(version_numbers[1]);
		}
	local this_software: software = [$name=software_name, $version=v];
	return this_software;
	}

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
	
# This can be used for &default values on tables when the index is an addr.
function addr_empty_string_set(a: addr): set[string]
	{
	return set();
	}

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
