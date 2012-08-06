
module Intel;

export {
	redef enum SubType += {
		DNS_ZONE,
	};
}

function dns_zone_ripper(query: Query): Query
	{
	local query_copy = copy(query);
	# We can assume that we're getting a string and subtype because
	# this function is only registered for DOMAIN and DNS_ZONE data.
	local dns_name = sub(query_copy$str, /^[^\.]*\./, "");
	query_copy$str = dns_name;
	# We are doing a literal search for a DNS zone at this point
	query_copy$subtype = Intel::DNS_ZONE;
	return query_copy;
	}

# This matcher extension adds additional matchers for domain names.
function dns_zone_matcher(query: Query): bool
	{
	local query_copy = dns_zone_ripper(query);
	if ( query$str == query_copy$str )
		return F;

	return Intel::matcher(query_copy);
	}

function dns_zone_lookup(query: Query): set[Item]
	{
	local result_set: set[Item] = set();
	local query_copy = dns_zone_ripper(query);
	if ( query$str == query_copy$str )
		return result_set;

	for ( item in Intel::lookup(query_copy) )
		add result_set[item];
	return result_set;
	}

event bro_init() &priority=10
	{
	register_custom_matcher(DOMAIN, dns_zone_matcher);
	# The DNS_ZONE subtype needs added because it's ultimately 
	# a subset of DOMAIN and will need to be searched as well.
	register_custom_matcher(DNS_ZONE, dns_zone_matcher);

	register_custom_lookup(DOMAIN, dns_zone_lookup);
	register_custom_lookup(DNS_ZONE, dns_zone_lookup);
	}
