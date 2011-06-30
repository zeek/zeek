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

## Takes a string and returns T or F if the string appears to be a full and 
## valid IP address.
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

## This outputs a string_array of ip addresses extracted from a string.
## given: "this is 1.1.1.1 a test 2.2.2.2 string with ip addresses 3.3.3.3"
## outputs: { [0] = 1.1.1.1, [1] = 2.2.2.2, [2] = 3.3.3.3 }
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
