# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

@load base/utils/addrs

event zeek_init()
	{
	print "============ test ipv4 regex (good strings)";
	local ip = "0.0.0.0";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "1.1.1.1";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "9.9.9.9";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "99.99.99.99";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "09.99.99.99";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "009.99.99.99";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "255.255.255.255";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	print "============ bad ipv4 decimals";
	ip = "255.255.255.256";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "255.255.255.295";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	ip = "255.255.255.300";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	print "============ too many ipv4 decimals";
	ip = "255.255.255.255.255";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	print "============ typical looking ipv4";
	ip = "192.168.1.100";
	print ip == ipv4_addr_regex;
	print is_valid_ip(ip);

	print "============ test ipv6 regex";

	ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
	print is_valid_ip(ip);

	# test for case insensitivity
	ip = "2001:0DB8:85A3:0000:0000:8A2E:0370:7334";
	print is_valid_ip(ip);

	# any case mixture is allowed
	ip = "2001:0dB8:85a3:0000:0000:8A2E:0370:7334";
	print is_valid_ip(ip);

	# leading zeroes of a 16-bit group may be omitted
	ip = "2001:db8:85a3:0:0:8a2e:370:7334";
	print is_valid_ip(ip);

	# a single occurrence of consecutive groups of zeroes may be replaced by ::
	ip = "2001:db8:85a3::8a2e:370:7334";
	print is_valid_ip(ip);

	# this should fail because we don't have enough 16-bit groups
	ip = "2001:db8:85a3:8a2e:370:7334";
	print is_valid_ip(ip);

	# this should fail because of an invalid hex digit
	ip = "2001:gb8:85a3::8a2e:370:7334";
	print is_valid_ip(ip);

	# this should fail because we have too many 16-bit groups
	ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1111";
	print is_valid_ip(ip);

	# this should fail because one group isn't 16-bits
	ip = "2001:0db8:85a3:0000:0000:8a2e00:0370:7334";
	print is_valid_ip(ip);

	# this should fail because we can't have more than one ::
	ip = "2001::85a3::7334";
	print is_valid_ip(ip);

	# all zeroes should work
	ip = "0:0:0:0:0:0:0:0";
	print is_valid_ip(ip);

	# all zeroes condensed should work
	ip = "::";
	print is_valid_ip(ip);

	print "============ test ipv6-ipv4 hybrid regexes";

	# hybrid ipv6-ipv4 address should work
	ip = "2001:db8:0:0:0:FFFF:192.168.0.5";
	print is_valid_ip(ip);

	# hybrid ipv6-ipv4 address with zero ommission should work
	ip = "2001:db8::FFFF:192.168.0.5";
	print is_valid_ip(ip);

	# hybrid format with more than six 16-bit groups should fail
	ip = "2001:db8:0:0:0:0:FFFF:192.168.0.5";
	print is_valid_ip(ip);

	# hybrid format without a 4 octet ipv4 part should fail
	ip = "2001:db8:0:0:0:FFFF:192.168.0";
	print is_valid_ip(ip);

	# hybrid format's ipv4 part should test that all octet's are 0-255
	ip = "2001:db8:0:0:0:FFFF:192.168.0.256";
	print is_valid_ip(ip);

	# These have too many hextets ("::" must expand to at least one hextet)
	print is_valid_ip("6:1:2::3:4:5:6:7");
	print is_valid_ip("6:1:2::3:4:5:6:7:8");

	print "============ test extract_ip_addresses()";
	print extract_ip_addresses("this is 1.1.1.1 a test 2.2.2.2 string with ip addresses 3.3.3.3");
	print extract_ip_addresses("this is 1.1.1.1 a test 0:0:0:0:0:0:0:0 string with ip addresses 3.3.3.3");
	print extract_ip_addresses("text 1.1.1.1 text", T);
	print extract_ip_addresses("text 1.1.1.1 text", F);
	print extract_ip_addresses("text1.1.1.1text", T);
	print extract_ip_addresses("text1.1.1.1text", F);
	print extract_ip_addresses("text[1.1.1.1]text", T);
	print extract_ip_addresses("text[1.1.1.1]text", F);
	print extract_ip_addresses("[1.1.1.1] [2.2.2.2]", T);
	print extract_ip_addresses("1.1.1.1", T);
	print extract_ip_addresses("1.1.1.1", F);

	# This will use the leading 6 from "IPv6" (maybe that's not intended
	# by a person trying to parse such a string, but that's just what's going
	# to happen; it's on them to deal).
	print extract_ip_addresses("IPv6:1:2::3:4:5:6:7");
	}
