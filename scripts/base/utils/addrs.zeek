##! Functions for parsing and manipulating IP and MAC addresses.

# Regular expressions for matching IP addresses in strings.

const ipv4_decim = /[0-9]{1}|[0-9]{2}|0[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]/;

const ipv4_addr_regex = ipv4_decim & /\./ & ipv4_decim & /\./ & ipv4_decim & /\./ & ipv4_decim;

const ipv6_hextet = /[0-9A-Fa-f]{1,4}/;

const ipv6_8hex_regex = /([0-9A-Fa-f]{1,4}:){7}/ & ipv6_hextet;

const ipv6_hex4dec_regex = /([0-9A-Fa-f]{1,4}:){6}/ & ipv4_addr_regex;

const ipv6_compressed_lead_hextets0 = /::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6})?/;

const ipv6_compressed_lead_hextets1 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,5})?/;

const ipv6_compressed_lead_hextets2 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){1}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4})?/;

const ipv6_compressed_lead_hextets3 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){2}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,3})?/;

const ipv6_compressed_lead_hextets4 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){3}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,2})?/;

const ipv6_compressed_lead_hextets5 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){4}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,1})?/;

const ipv6_compressed_lead_hextets6 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){5}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,0})?/;

const ipv6_compressed_lead_hextets7 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){6}::/;

const ipv6_compressed_hex_regex = ipv6_compressed_lead_hextets0 |
                                  ipv6_compressed_lead_hextets1 |
                                  ipv6_compressed_lead_hextets2 |
                                  ipv6_compressed_lead_hextets3 |
                                  ipv6_compressed_lead_hextets4 |
                                  ipv6_compressed_lead_hextets5 |
                                  ipv6_compressed_lead_hextets6 |
                                  ipv6_compressed_lead_hextets7;

const ipv6_compressed_hext4dec_lead_hextets0 = /::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4})?/ & ipv4_addr_regex;

const ipv6_compressed_hext4dec_lead_hextets1 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,3})?/ & ipv4_addr_regex;

const ipv6_compressed_hext4dec_lead_hextets2 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){1}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,2})?/ & ipv4_addr_regex;

const ipv6_compressed_hext4dec_lead_hextets3 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){2}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,1})?/ & ipv4_addr_regex;

const ipv6_compressed_hext4dec_lead_hextets4 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){3}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,0})?/ & ipv4_addr_regex;

const ipv6_compressed_hext4dec_lead_hextets5 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){4}::/ & ipv4_addr_regex;

const ipv6_compressed_hex4dec_regex = ipv6_compressed_hext4dec_lead_hextets0 |
                                      ipv6_compressed_hext4dec_lead_hextets1 |
                                      ipv6_compressed_hext4dec_lead_hextets2 |
                                      ipv6_compressed_hext4dec_lead_hextets3 |
                                      ipv6_compressed_hext4dec_lead_hextets4 |
                                      ipv6_compressed_hext4dec_lead_hextets5;

const ipv6_addr_regex = ipv6_8hex_regex |
                        ipv6_compressed_hex_regex |
                        ipv6_hex4dec_regex |
                        ipv6_compressed_hex4dec_regex;

const ip_addr_regex = ipv4_addr_regex | ipv6_addr_regex;

## Checks if all elements of a string array are a valid octet value.
##
## octets: an array of strings to check for valid octet values.
##
## Returns: T if every element is between 0 and 255, inclusive, else F.
function has_valid_octets(octets: string_vec): bool
	{
	for ( i in octets )
		{
		local num = to_count(octets[i]);
		if ( 255 < num )
			return F;
		}
	return T;
	}

## Extracts all IP (v4 or v6) address strings from a given string.
##
## input: a string that may contain an IP address anywhere within it.
##
## check_wrapping: if true, will only return IP addresses that are wrapped in matching
## pairs of spaces, square brackets, curly braces, or parens. This can be used to avoid
## extracting strings that look like IPs from innocuous strings, such as SMTP headers.
##
## Returns: an array containing all valid IP address strings found in *input*.
function extract_ip_addresses(input: string, check_wrapping: bool &default=F): string_vec
	{
	local parts = split_string_all(input, ip_addr_regex);
	local output: string_vec;

	for ( i in parts )
		{
		if ( i % 2 == 1 && is_valid_ip(parts[i]) )
			{
			if ( ! check_wrapping )
				{
				output += parts[i];
				}
			else if ( i > 0 && i < |parts| - 1 )
				{
				local p1 = parts[i-1];
				local p3 = parts[i+1];

				if ( ( |p1| == 0 && |p3| == 0 ) ||
				     ( p1[-1] == "\[" && p3[0] == "\]" ) ||
			             ( p1[-1] == "\(" && p3[0] == "\)" ) ||
			             ( p1[-1] == "\{" && p3[0] == "\}" ) ||
			             ( p1[-1] == " " && p3[0] == " " ) )
					output += parts[i];
				}
			}
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
		octets = str_split_indices(result, vector(2, 4, 6, 8, 10));
		return fmt("%s:%s:%s:%s:%s:%s", octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]);
		}

	if ( |result| == 16 )
		{
		octets = str_split_indices(result, vector(2, 4, 6, 8, 10, 12, 14));
		return fmt("%s:%s:%s:%s:%s:%s:%s:%s", octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]);
		}

	return "";
	}
