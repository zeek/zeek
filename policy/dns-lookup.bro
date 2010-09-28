# $Id: dns-lookup.bro 340 2004-09-09 06:38:27Z vern $

@load notice

redef enum Notice += {
	DNS_MappingChanged,	# some sort of change WRT previous Bro lookup
};

const dns_interesting_changes = {
	"unverified", "old name", "new name", "mapping",
} &redef;

function dump_dns_mapping(msg: string, dm: dns_mapping): bool
	{
	if ( msg in dns_interesting_changes ||
	     127.0.0.1 in dm$addrs )
		{
		local req = dm$req_host == "" ?
				fmt("%As", dm$req_addr) : dm$req_host;
		NOTICE([$note=DNS_MappingChanged,
			$msg=fmt("DNS %s: %s/%s %s-> %As", msg, req,
					dm$hostname, dm$valid ?
						"" : "(invalid) ", dm$addrs),
			$sub=msg]);

		return T;
		}
	else
		return F;
	}

event dns_mapping_valid(dm: dns_mapping)
	{
	dump_dns_mapping("valid", dm);
	}

event dns_mapping_unverified(dm: dns_mapping)
	{
	dump_dns_mapping("unverified", dm);
	}

event dns_mapping_new_name(dm: dns_mapping)
	{
	dump_dns_mapping("new name", dm);
	}

event dns_mapping_lost_name(dm: dns_mapping)
	{
	dump_dns_mapping("lost name", dm);
	}

event dns_mapping_name_changed(old_dm: dns_mapping, new_dm: dns_mapping)
	{
	if ( dump_dns_mapping("old name", old_dm) )
		dump_dns_mapping("new name", new_dm);
	}

event dns_mapping_altered(dm: dns_mapping,
				old_addrs: set[addr], new_addrs: set[addr])
	{
	if ( dump_dns_mapping("mapping", dm) )
		NOTICE([$note=DNS_MappingChanged,
			$msg=fmt("changed addresses: %As -> %As", old_addrs, new_addrs),
			$sub="changed addresses"]);
	}
