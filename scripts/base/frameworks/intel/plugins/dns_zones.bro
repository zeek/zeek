
module Intel;

export {
	redef enum SubType += {
		DNS_ZONE,
	};
}

function dns_zone_ripper(found: Found): Found
	{
	local found_copy = copy(found);

	## # We only support fourth level depth zones right now for performance.
	## if ( /(\.[^\.]+){4,}/ in found_copy$str )
	## 	{
	## 	local parts = split_all(found_copy$str, /\./);
	## 	local len = |parts|;
	## 	found_copy$str = parts[len-6] + "." + parts[len-4] + "." + parts[len-2] + "." + parts[len];
	## 	}

	# We can assume that we're getting a string and subtype because
	# this function is only registered for DOMAIN and DNS_ZONE data.
	local dns_name = sub(found_copy$str, /^[^\.]*\./, "");
	found_copy$str = dns_name;
	# We are doing a literal search for a DNS zone at this point
	found_copy$str_type = Intel::DNS_ZONE;
	return found_copy;
	}

# This matcher extension adds additional matchers for domain names.
function dns_zone_matcher(found: Found): bool
	{
	local found_copy = dns_zone_ripper(found);
	if ( found$str == found_copy$str )
		return F;

	return Intel::find(found_copy);
	}

function dns_zone_lookup(found: Found): set[Item]
	{
	local result_set: set[Item] = set();
	local found_copy = dns_zone_ripper(found);
	if ( found$str == found_copy$str )
		return result_set;

	for ( item in Intel::lookup(found_copy) )
		add result_set[item];
	return result_set;
	}

event bro_init() &priority=10
	{
	register_custom_matcher(DOMAIN, dns_zone_matcher);
	register_custom_lookup(DOMAIN, dns_zone_lookup);
	## The DNS_ZONE subtype needs added because it's ultimately 
	## a subset of DOMAIN and will need to be searched as well.
	register_custom_matcher(DNS_ZONE, dns_zone_matcher);
	register_custom_lookup(DNS_ZONE, dns_zone_lookup);
	}
