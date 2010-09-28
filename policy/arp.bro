# $Id: arp.bro 4909 2007-09-24 02:26:36Z vern $

@load notice

module ARP;

export {
	redef enum Notice += {
		ARPSourceMAC_Mismatch,	# source MAC doesn't match mappings
		ARPAddlMAC_Mapping,	# another MAC->addr seen beyond just one
		ARPUnsolicitedReply,	# could be poisoning; or just gratuitous
		# ARPRequestProvidesTargetAddr,	# request includes non-triv addr

		# MAC/addr pair seen in request/reply different from
		# that in the cache.
		ARPCacheInconsistency,

		# ARP reply gives different value than previously seen.
		ARPMappingChanged,
	};

	const arp_log = open_log_file("arp") &redef;
}

redef capture_filters += { ["arp"] = "arp" };

# Abbreviations taken from RFC 826:
#
# SHA: source hardware address
# SPA: source protocol address (i.e., IP address)
# THA: target hardware address
# TPA: target protocol address

# ARP requests indexed on SHA/SPA/TPA (no THA, as it's what it's being
# queried).
global arp_requests: set[string, addr, addr] &create_expire = 1 min;

# ARP responses we've seen: indexed by IP address, yielding MAC address.
global ARP_cache: table[addr] of string;


# Bad ARPs can occur when:
#	- type/size pairs are not OK for HW and L3 addresses (Ethernet=6, IP=4)
#	- opcode is neither request (1) nor reply (2)
#	- MAC src address != ARP sender MAC address
event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string,
		explanation: string)
	{
	print arp_log, fmt("%.06f bad-arp %s(%s) ? %s(%s): %s",
			network_time(), SPA, SHA, TPA, THA, explanation);
	}


# The first of these maps a MAC address to the last protocol address seen
# for it.  The second tracks every protocol address seen.
global mac_addr_map: table[string] of addr;
global mac_addr_associations: table[string] of set[addr];

# A somewhat general notion of broadcast MAC/IP addresses.
const broadcast_mac_addrs = { "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", };
const broadcast_addrs = { 0.0.0.0, 255.255.255.255, };


# Called to note that we've seen an association between a MAC address
# and an IP address.  Note that this is *not* an association advertised
# in an ARP reply (those are tracked in ARP_cache), but instead the
# pairing of hardware address + protocol address as expressed in
# an ARP request or reply header.
function mac_addr_association(mac_addr: string, a: addr)
	{
	# Ignore placeholders.
	if ( mac_addr in broadcast_mac_addrs || a in broadcast_addrs )
		return;

	local is_addl = F;
	if ( mac_addr in mac_addr_associations )
		is_addl = a !in mac_addr_associations[mac_addr];
	else
		mac_addr_associations[mac_addr] = set();

	print arp_log, fmt("%.06f association %s -> %s%s", network_time(),
				mac_addr, a, is_addl ? " <addl>" : "");

	mac_addr_map[mac_addr] = a;
	add mac_addr_associations[mac_addr][a];

	if ( a in ARP_cache && ARP_cache[a] != mac_addr )
		NOTICE([$note=ARPCacheInconsistency, $src=a,
			$msg=fmt("mapping for %s to %s doesn't match cache of %s",
				mac_addr, a, ARP_cache[a])]);
	}

# Returns the IP address associated with a MAC address, if we've seen one.
# Otherwise just returns the MAC address.
function addr_from_mac(mac_addr: string): string
	{
	return mac_addr in mac_addr_map ?
		fmt("%s", mac_addr_map[mac_addr]) : mac_addr;
	}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string,
			TPA: addr, THA: string)
	{
	mac_addr_association(SHA, SPA);

	local msg = fmt("%s -> %s who-has %s",
			addr_from_mac(mac_src), addr_from_mac(mac_dst), TPA);

	local mismatch = SHA != mac_src;
	if ( mismatch )
		NOTICE([$note=ARPSourceMAC_Mismatch, $src=SPA, $msg=msg]);

	# It turns out that some hosts fill in the THA field even though
	# that doesn't make sense.  (The RFC specifically allows this,
	# however.)  Perhaps there's an attack that can be launched
	# doing so, but it's hard to see what it might be, so for now
	# we don't bother notice'ing these.
	# if ( THA !in broadcast_addrs )
	# 	NOTICE([$note=ARPRequestProvidesTargetAddr, $src=SPA,
	# 		$msg=fmt("%s: %s", msg, THA)]);

	print arp_log, fmt("%.06f %s%s", network_time(), msg,
				mismatch ? " <source-mismatch>" : "");

	add arp_requests[SHA, SPA, TPA];
	}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string,
		TPA: addr, THA: string)
	{
	mac_addr_association(SHA, SPA);
	mac_addr_association(THA, TPA);

	local msg = fmt("%s -> %s: %s is-at %s",
			addr_from_mac(mac_src), addr_from_mac(mac_dst),
			SPA, SHA);

	local unsolicited = [THA, TPA, SPA] !in arp_requests;
	delete arp_requests[THA, TPA, SPA];
	if ( unsolicited )
		NOTICE([$note=ARPUnsolicitedReply, $src=SPA,
			$msg=fmt("%s: request[%s, %s, %s]", msg, THA, TPA, SPA)]);

	local mismatch = SHA != mac_src;
	if ( mismatch )
		NOTICE([$note=ARPSourceMAC_Mismatch, $src=SPA, $msg=msg]);

	local mapping_changed = SPA in ARP_cache && ARP_cache[SPA] != SHA;
	if ( mapping_changed )
		NOTICE([$note=ARPMappingChanged, $src=SPA,
			$msg=fmt("%s: was %s", msg, ARP_cache[SPA])]);

	print arp_log, fmt("%.06f %s%s%s%s", network_time(), msg,
				unsolicited ? " <unsolicited>" : "",
				mismatch ? " <source-mismatch>" : "",
				mapping_changed ?
					fmt(" <changed from %s>", ARP_cache[SPA]) : "");

	ARP_cache[SPA] = SHA;
	}
