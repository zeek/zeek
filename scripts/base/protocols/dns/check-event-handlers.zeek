##! This script checks if DNS event handlers that will not be raised
##! are used and raises a warning in those cases.

module DNS;

event zeek_init() &priority=20
	{
	if ( ! dns_skip_all_addl )
		return;

	local addl_functions = ["dns_TSIG_addl", "dns_EDNS_addl", "dns_EDNS_ecs", "dns_EDNS_tcp_keepalive", "dns_EDNS_cookie"];

	for ( event_name in addl_functions )
		if ( is_event_handled(event_name) )
			Reporter::warning(fmt("Used event '%s' will not be raised because 'dns_skip_all_addl' is true", event_name));

	if ( is_event_handled("dns_TKEY") )
		Reporter::warning("Used event 'dns_TKEY' will not contain any data in 'ans' because 'dns_skip_all_addl' is true");
	}
