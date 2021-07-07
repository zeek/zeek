##! Definitions describing a site - which networks and DNS zones are "local"
##! and "neighbors", and servers running particular services.
@load ./patterns

module Site;

export {
	## A list of subnets that are considered private address space.
	##
	## By default, it has address blocks defined by IANA as not being routable over the Internet.
	##
	## See the `IPv4 Special-Purpose Address Registry <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>`_
	## and the `IPv6 Special-Purpose Address Registry <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>`_
	option private_address_space: set[subnet] = {
		## "This network", see :rfc:`791`
		0.0.0.0/8,
		## Private-Use, see :rfc:`1918`
		10.0.0.0/8,
		## Shared Address Space (also known as Carrier-grade NAT), see :rfc:`6598`
		100.64.0.0/10,
		## Loopback, see :rfc:`1122`
		127.0.0.0/8,
		## Link Local, see :rfc:`3927`
		169.254.0.0/16,
		## Private-Use, see :rfc:`1918`
		172.16.0.0/12,
		## IETF Protocol Assignments, see :rfc:`6890`
		192.0.0.0/24,
		## Documentation (TEST-NET-1), see :rfc:`5737`
		192.0.2.0/24,
		## Private-Use, see :rfc:`1918`
		192.168.0.0/16,
		## Benchmarking, see :rfc:`2544`
		198.18.0.0/15,
		## Documentation (TEST-NET-2), see :rfc:`5737`
		198.51.100.0/24,
		## Documentation (TEST-NET-3), see :rfc:`5737`
		203.0.113.0/24,
		## Reserved, see :rfc:`1112`
		240.0.0.0/4,
		## Limited Broadcast, see :rfc:`919` and :rfc:`8190`
		255.255.255.255/32,
		
		## Unspecified Address, see :rfc:`4291`
		[::]/128,
		## Loopback Address, see :rfc:`4291`
		[::1]/128,
		## IPv4-mapped Address, see :rfc:`4291`
		[::ffff:0:0]/96,
		## IPv4-IPv6 Translation, see :rfc:`8215`
		[64:ff9b:1::]/48,
		## Discard-Only Address Block, see :rfc:`6666`
		[100::]/64,
		## IETF Protocol Assignments, see :rfc:`2928`
		[2001::]/23,
		## Benchmarking, see :rfc:`5180`
		[2001:2::]/48,
		## Documentation, see :rfc:`3849`
		[2001:db8::]/32,
		## Unique-Local, see :rfc:`4193` and :rfc:`8190`
		[fc00::]/7,
		## Link-Local Unicast, see :rfc:`4291`
		[fe80::]/10,
	};

	## Networks that are considered "local".  Note that ZeekControl sets
	## this automatically.
	option local_nets: set[subnet] = {};

	## This is used for retrieving the subnet when using multiple entries in
	## :zeek:id:`Site::local_nets`.  It's populated automatically from there.
	## A membership query can be done with an
	## :zeek:type:`addr` and the table will yield the subnet it was found
	## within.
	global local_nets_table: table[subnet] of subnet = {};

	## Networks that are considered "neighbors".
	option neighbor_nets: set[subnet] = {};

	## If local network administrators are known and they have responsibility
	## for defined address space, then a mapping can be defined here between
	## networks for which they have responsibility and a set of email
	## addresses.
	option local_admins: table[subnet] of set[string] = {};

	## DNS zones that are considered "local".
	option local_zones: set[string] = {};

	## DNS zones that are considered "neighbors".
	option neighbor_zones: set[string] = {};

	## Function that returns true if an address corresponds to one of
	## the local networks, false if not.
	## The function inspects :zeek:id:`Site::local_nets`.
	global is_local_addr: function(a: addr): bool;

	## Function that returns true if an address corresponds to one of
	## the neighbor networks, false if not.
	## The function inspects :zeek:id:`Site::neighbor_nets`.
	global is_neighbor_addr: function(a: addr): bool;

	## Function that returns true if an address corresponds to one of
	## the private/unrouted networks, false if not.
	## The function inspects :zeek:id:`Site::private_address_space`.
	global is_private_addr: function(a: addr): bool;

	## Function that returns true if a host name is within a local
	## DNS zone.
	## The function inspects :zeek:id:`Site::local_zones`.
	global is_local_name: function(name: string): bool;

	## Function that returns true if a host name is within a neighbor
	## DNS zone.
	## The function inspects :zeek:id:`Site::neighbor_zones`.
	global is_neighbor_name: function(name: string): bool;

	## Function that returns a comma-separated list of email addresses
	## that are considered administrators for the IP address provided as
	## an argument.
	## The function inspects :zeek:id:`Site::local_admins`.
	global get_emails: function(a: addr): string;
}

# Please ignore, this is an interally used variable.
global local_dns_suffix_regex: pattern = /MATCH_NOTHING/;
global local_dns_neighbor_suffix_regex: pattern = /MATCH_NOTHING/;


function is_local_addr(a: addr): bool
	{
	return a in local_nets;
	}

function is_neighbor_addr(a: addr): bool
	{
	return a in neighbor_nets;
	}

function is_private_addr(a: addr): bool
	{
	return a in private_address_space;
	}

function is_local_name(name: string): bool
	{
	return local_dns_suffix_regex in name;
	}

function is_neighbor_name(name: string): bool
	{
	return local_dns_neighbor_suffix_regex in name;
	}

# This is a hack for doing a for loop.
const one_to_32: vector of count = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};

# TODO: make this work with IPv6
function find_all_emails(ip: addr): set[string]
	{
	if ( ip !in local_admins ) return set();

	local output_values: set[string] = set();
	local tmp_subnet: subnet;
	local i: count;
	local emails: string;
	for ( i in one_to_32 )
		{
		tmp_subnet = mask_addr(ip, one_to_32[i]);
		if ( tmp_subnet in local_admins )
			for ( email in local_admins[tmp_subnet] )
				{
				if ( email != "" )
					add output_values[email];
			}
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

function get_emails(a: addr): string
	{
	return fmt_email_string(find_all_emails(a));
	}

event zeek_init() &priority=10
	{
	# Double backslashes are needed due to string parsing.
	local_dns_suffix_regex = set_to_regex(local_zones, "(^\\.?|\\.)(~~)$");
	local_dns_neighbor_suffix_regex = set_to_regex(neighbor_zones, "(^\\.?|\\.)(~~)$");

	# Create the local_nets mapping table.
	for ( cidr in Site::local_nets )
		local_nets_table[cidr] = cidr;

	}
