##! Functions for parsing and manipulating IP addresses.

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
function has_valid_octets(octets: string_array): bool
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
	local octets: string_array;
	if ( ip_str == ipv4_addr_regex )
		{
		octets = split(ip_str, /\./);
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
			octets = split(ip_str, /\./);
			if ( |octets| != 4 )
				return F;

			# get rid of remaining IPv6 stuff in first octet
			local tmp = split(octets[1], /:/);
			octets[1] = tmp[|tmp|];

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
function find_ip_addresses(input: string): string_array
	{
	local parts = split_all(input, ip_addr_regex);
	local output: string_array;

	for ( i in parts )
		{
		if ( i % 2 == 0 && is_valid_ip(parts[i]) )
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
