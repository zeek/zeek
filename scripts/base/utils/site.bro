##! Definitions describing a site - which networks and DNS zones are "local"
##! and "neighbors", and servers running particular services.
@load ./patterns

module Site;

export {
	## Address space that is considered private and unrouted.
	## By default it has RFC defined non-routable IPv4 address space.
	const private_address_space: set[subnet] = {
		10.0.0.0/8,
		192.168.0.0/16,
		172.16.0.0/12,
		100.64.0.0/10,  # RFC6598 Carrier Grade NAT
		127.0.0.0/8,
		[fe80::]/10,
		[::1]/128,
	} &redef;

	## Networks that are considered "local".  Note that BroControl sets
	## this automatically.
	const local_nets: set[subnet] &redef;

	## This is used for retrieving the subnet when using multiple entries in
	## :bro:id:`Site::local_nets`.  It's populated automatically from there.
	## A membership query can be done with an
	## :bro:type:`addr` and the table will yield the subnet it was found
	## within.
	global local_nets_table: table[subnet] of subnet = {};

	## Networks that are considered "neighbors".
	const neighbor_nets: set[subnet] &redef;

	## If local network administrators are known and they have responsibility
	## for defined address space, then a mapping can be defined here between
	## networks for which they have responsibility and a set of email
	## addresses.
	const local_admins: table[subnet] of set[string] = {} &redef;

	## DNS zones that are considered "local".
	const local_zones: set[string] &redef;

	## DNS zones that are considered "neighbors".
	const neighbor_zones: set[string] &redef;

	## Function that returns true if an address corresponds to one of
	## the local networks, false if not.
	## The function inspects :bro:id:`Site::local_nets`.
	global is_local_addr: function(a: addr): bool;

	## Function that returns true if an address corresponds to one of
	## the neighbor networks, false if not.
	## The function inspects :bro:id:`Site::neighbor_nets`.
	global is_neighbor_addr: function(a: addr): bool;

	## Function that returns true if an address corresponds to one of
	## the private/unrouted networks, false if not.
	## The function inspects :bro:id:`Site::private_address_space`.
	global is_private_addr: function(a: addr): bool;

	## Function that returns true if a host name is within a local
	## DNS zone.
	## The function inspects :bro:id:`Site::local_zones`.
	global is_local_name: function(name: string): bool;

	## Function that returns true if a host name is within a neighbor
	## DNS zone.
	## The function inspects :bro:id:`Site::neighbor_zones`.
	global is_neighbor_name: function(name: string): bool;

	## Function that returns a comma-separated list of email addresses
	## that are considered administrators for the IP address provided as
	## an argument.
	## The function inspects :bro:id:`Site::local_admins`.
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
		for ( email in local_admins[tmp_subnet] )
			{
			for ( email in local_admins[tmp_subnet] )
				{
				if ( email != "" )
					add output_values[email];
				}
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

event bro_init() &priority=10
	{
	# Double backslashes are needed due to string parsing.
	local_dns_suffix_regex = set_to_regex(local_zones, "(^\\.?|\\.)(~~)$");
	local_dns_neighbor_suffix_regex = set_to_regex(neighbor_zones, "(^\\.?|\\.)(~~)$");

	# Create the local_nets mapping table.
	for ( cidr in Site::local_nets )
		local_nets_table[cidr] = cidr;

	}
