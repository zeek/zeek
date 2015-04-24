##! Functions for parsing and manipulating IP and MAC addresses.

# Regular expressions for matching IP addresses in strings.
const ipv4_addr_regex = /[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}/;
const ipv6_8hex_regex = /([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/;
const ipv6_compressed_hex_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)/;
const ipv6_hex4dec_regex = /(([0-9A-Fa-f]{1,4}:){6,6})([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;
const ipv6_compressed_hex4dec_regex = /(([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::(([0-9A-Fa-f]{1,4}:)*)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;

# These are commented out until patterns can be constructed this way at init time.
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

## Checks if all elements of a string array are a valid octet value.
##
## octets: an array of strings to check for valid octet values.
##
## Returns: T if every element is between 0 and 255, inclusive, else F.
function has_valid_octets(octets: string_vec): bool
	{
	local num = 0;
	for ( i in octets )
		{
		num = to_count(octets[i]);
		if ( num < 0 || 255 < num )
			return F;
		}
	return T;
	}

## Checks if a string appears to be a valid IPv4 or IPv6 address.
##
## ip_str: the string to check for valid IP formatting.
##
## Returns: T if the string is a valid IPv4 or IPv6 address format.
function is_valid_ip(ip_str: string): bool
	{
	local octets: string_vec;
	if ( ip_str == ipv4_addr_regex )
		{
		octets = split_string(ip_str, /\./);
		if ( |octets| != 4 )
			return F;

		return has_valid_octets(octets);
		}
	else if ( ip_str == ipv6_addr_regex )
		{
		if ( ip_str == ipv6_hex4dec_regex ||
		     ip_str == ipv6_compressed_hex4dec_regex )
			{
			# the regexes for hybrid IPv6-IPv4 address formats don't for valid
			# octets within the IPv4 part, so do that now
			octets = split_string(ip_str, /\./);
			if ( |octets| != 4 )
				return F;

			# get rid of remaining IPv6 stuff in first octet
			local tmp = split_string(octets[0], /:/);
			octets[0] = tmp[|tmp| - 1];

			return has_valid_octets(octets);
			}
		else
			{
			# pure IPv6 address formats that only use hex digits don't need
			# any additional checks -- the regexes should be complete
			return T;
			}
		}
	return F;
	}

## Extracts all IP (v4 or v6) address strings from a given string.
##
## input: a string that may contain an IP address anywhere within it.
##
## Returns: an array containing all valid IP address strings found in *input*.
function find_ip_addresses(input: string): string_array &deprecated
	{
	local parts = split_string_all(input, ip_addr_regex);
	local output: string_array;

	for ( i in parts )
		{
		if ( i % 2 == 1 && is_valid_ip(parts[i]) )
			output[|output|] = parts[i];
		}
	return output;
	}

## Extracts all IP (v4 or v6) address strings from a given string.
##
## input: a string that may contain an IP address anywhere within it.
##
## Returns: an array containing all valid IP address strings found in *input*.
function extract_ip_addresses(input: string): string_vec
	{
	local parts = split_string_all(input, ip_addr_regex);
	local output: string_vec;

	for ( i in parts )
		{
		if ( i % 2 == 1 && is_valid_ip(parts[i]) )
			output[|output|] = parts[i];
		}
	return output;
	}

## Returns the string representation of an IP address suitable for inclusion
## in a URI.  For IPv4, this does no special formatting, but for IPv6, the
## address is included in square brackets.
##
## a: the address to make suitable for URI inclusion.
##
## Returns: the string representation of the address suitable for URI inclusion.
function addr_to_uri(a: addr): string
	{
	if ( is_v4_addr(a) )
		return fmt("%s", a);
	else
		return fmt("[%s]", a);
	}

## Given a string, extracts the hex digits and returns a MAC address in
## the format: 00:a0:32:d7:81:8f. If the string doesn't contain 12 or 16 hex
## digits, an empty string is returned.
##
## a: the string to normalize.
##
## Returns: a normalized MAC address, or an empty string in the case of an error.
function normalize_mac(a: string): string
	{
	local result = to_lower(gsub(a, /[^A-Fa-f0-9]/, ""));
	local octets: string_vec;

	if ( |result| == 12 )
		{
		octets = str_split(result, vector(2, 4, 6, 8, 10));
		return fmt("%s:%s:%s:%s:%s:%s", octets[1], octets[2], octets[3], octets[4], octets[5], octets[6]);
		}

	if ( |result| == 16 )
		{
		octets = str_split(result, vector(2, 4, 6, 8, 10, 12, 14));
		return fmt("%s:%s:%s:%s:%s:%s:%s:%s", octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7], octets[8]);
		}

	return "";
	}
