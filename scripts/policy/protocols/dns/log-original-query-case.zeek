##! This script adds the query with its original letter casing
##! to the DNS log.

@load base/protocols/dns/main

module DNS;

export {
	redef record Info += {
		## Query with original letter casing
		original_query: string &log &optional;
	};
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) &priority=5
	{
	if ( msg$opcode != 0 )
		# Currently only standard queries are tracked.
		return;

	c$dns$original_query = original_query;
	}
