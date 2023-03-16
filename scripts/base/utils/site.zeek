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
		# "This network", see :rfc:`791`
		0.0.0.0/8,
		# 0.0.0.0/8 as a 6to4 address, see :rfc:`791` and :rfc:`3056`
		[2002::]/24,

		# Private-Use, see :rfc:`1918`
		10.0.0.0/8,
		# 10.0.0.0/8 as a 6to4 address, see :rfc:`1918` and :rfc:`3056`
		[2002:a00::]/24,

		# Shared Address Space (also known as Carrier-grade NAT), see :rfc:`6598`
		100.64.0.0/10,
		# 100.64.0.0/10 as a 6to4 address, see :rfc:`6598` and :rfc:`3056`
		[2002:6440::]/26,

		# Loopback, see :rfc:`1122`
		127.0.0.0/8,
		# 127.0.0.0/8 as a 6to4 address, see :rfc:`1122` and :rfc:`3056`
		[2002:7f00::]/24,

		# Link Local, see :rfc:`3927`
		169.254.0.0/16,
		# 169.254.0.0/16 as a 6to4 address, see :rfc:`3927` and :rfc:`3056`
		[2002:a9fe::]/32,

		# Private-Use, see :rfc:`1918`
		172.16.0.0/12,
		# 172.16.0.0/12 as a 6to4 address, see :rfc:`1918` and :rfc:`3056`
		[2002:ac10::]/28,

		# IETF Protocol Assignments, see :rfc:`6890`
		192.0.0.0/24,
		# 192.0.0.0/24 as a 6to4 address, see :rfc:`6890` and :rfc:`3056`
		[2002:c000::]/40,

		# Documentation (TEST-NET-1), see :rfc:`5737`
		192.0.2.0/24,
		# 192.0.2.0/24 as a 6to4 address, see :rfc:`5737` and :rfc:`3056`
		[2002:c000:200::]/40,

		# Private-Use, see :rfc:`1918`
		192.168.0.0/16,
		# 192.168.0.0/16 as a 6to4 address, see :rfc:`1918` and :rfc:`3056`
		[2002:c0a8::]/32,

		# Benchmarking, see :rfc:`2544`
		198.18.0.0/15,
		# 198.18.0.0/15 as a 6to4 address, see :rfc:`2544` and :rfc:`3056`
		[2002:c612::]/31,

		# Documentation (TEST-NET-2), see :rfc:`5737`
		198.51.100.0/24,
		# 198.51.100.0/24 as a 6to4 address, see :rfc:`5737` and :rfc:`3056`
		[2002:c633:6400::]/40,

		# Documentation (TEST-NET-3), see :rfc:`5737`
		203.0.113.0/24,
		# 203.0.113.0/24 as a 6to4 address, see :rfc:`5737` and :rfc:`3056`
		[2002:cb00:7100::]/40,

		# Reserved, see :rfc:`1112`
		240.0.0.0/4,
		# 240.0.0.0/4 as a 6to4 address, see :rfc:`1112` and :rfc:`3056`
		[2002:f000::]/20,

		# Limited Broadcast, see :rfc:`919` and :rfc:`8190`
		255.255.255.255/32,
		# 255.255.255.255/32 as a 6to4 address, see :rfc:`8190` and :rfc:`3056`
		[2002:ffff:ffff::]/48,


		# Unspecified Address, see :rfc:`4291`
		[::]/128,
		# Loopback Address, see :rfc:`4291`
		[::1]/128,
		# IPv4-IPv6 Translation, see :rfc:`8215`
		[64:ff9b:1::]/48,
		# Discard-Only Address Block, see :rfc:`6666`
		[100::]/64,
		# IETF Protocol Assignments, see :rfc:`2928`
		[2001::]/23,
		# Benchmarking, see :rfc:`5180`
		[2001:2::]/48,
		# Documentation, see :rfc:`3849`
		[2001:db8::]/32,
		# Unique-Local, see :rfc:`4193` and :rfc:`8190`
		[fc00::]/7,
		# Link-Local Unicast, see :rfc:`4291`
		[fe80::]/10,
	};

	## Networks that are considered "local".  Note that ZeekControl sets
	## this automatically.
	option local_nets: set[subnet] = {};

	## Whether Zeek should automatically consider private address ranges
	## "local". On by default, this setting ensures that the initial value
	## of :zeek:id:`Site::private_address_space` as well as any later
	## updates to it get copied over into :zeek:id:`Site::local_nets`.
	const private_address_space_is_local = T &redef;

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

# A state bit to indicate to the Site::local_nets change handler whether it
# still needs to take into account Site::private_address_space.
global local_nets_needs_private_address_space = T;

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

function update_local_nets_table(id: string, new_value: set[subnet]): set[subnet]
	{
	local result = new_value;

	# If private address ranges are to be local, ensure they remain
	# in Site::local_nets during this update. If we just got here
	# because Site::private_address_space got updated, use the pending
	# state its change handler created.
	if ( private_address_space_is_local )
		{
		if ( local_nets_needs_private_address_space )
			result = new_value | Site::private_address_space;
		local_nets_needs_private_address_space = T;
		}

	# Refresh the local_nets mapping table.
	local_nets_table = {};

	for ( cidr in result )
		local_nets_table[cidr] = cidr;

	return result;
	}

function update_local_zones_regex(id: string, new_value: set[string]): set[string]
	{
	# Double backslashes are needed due to string parsing.
	local_dns_suffix_regex = set_to_regex(new_value, "(^\\.?|\\.)(~~)$");
	return new_value;
	}

function update_neighbor_zones_regex(id: string, new_value: set[string]): set[string]
	{
	local_dns_neighbor_suffix_regex = set_to_regex(new_value, "(^\\.?|\\.)(~~)$");
	return new_value;
	}

function update_private_address_space(id: string, new_value: set[subnet]): set[subnet]
	{
	# This change handler mirrors the changes to private ranges into
	# Site::local_nets. It does not use clusterization: the update to the
	# private address space already propagates, so we just apply the change
	# locally.
	local new_privates = new_value - private_address_space;
	local old_privates = private_address_space - new_value;

	# Compute the update to local nets here. Note that local_nets may not
	# yet have the private-space additions, if this is running at startup,
	# so we merge it explicitly, and then apply the deltas:
	local new_local_nets = (local_nets | private_address_space) - old_privates;
	new_local_nets += new_privates; # Can't currently chain +/- set ops.

	# Subtle: calling Option::set() on Site::local_nets will cause its
	# change handler update_local_nets_table() to trigger directly. It
	# normally adds Site::private_address_space to Site::local_nets, but the
	# former will still have its old value since this change handler hasn't
	# returned yet. Since we just computed the new local_nets value above,
	# we can signal to the change handler that adding
	# Site::private_address_space is not required:
	local_nets_needs_private_address_space = F;

	# The special location value "<skip-config-log"> signals to the config
	# framework's own catch-all change handler that this update is internal
	# and need not be logged.
	Option::set("Site::local_nets", new_local_nets, "<skip-config-log>");

	return new_value;
	}

event zeek_init() &priority=10
	{
	# Have these run with a lower priority so we account for additions/removals
	# from user created change handlers.
	Option::set_change_handler("Site::local_nets", update_local_nets_table, -5);
	Option::set_change_handler("Site::local_zones", update_local_zones_regex, -5);
	Option::set_change_handler("Site::neighbor_zones", update_neighbor_zones_regex, -5);

	# If private address ranges are to be local, add a change handler to sync
	# these over in the future, and trigger it once to bring local_nets up
	# to speed immediately.
	if ( private_address_space_is_local )
		{
		Option::set_change_handler("Site::private_address_space", update_private_address_space, -5);
		update_private_address_space("Site::private_address_space", Site::private_address_space);
		}

	# Use change handler to initialize local_nets mapping table and zones
	# regexes.
	update_local_nets_table("Site::local_nets", Site::local_nets);
	update_local_zones_regex("Site::local_zones", Site::local_zones);
	update_neighbor_zones_regex("Site::neighbor_zones", Site::neighbor_zones);
	}
