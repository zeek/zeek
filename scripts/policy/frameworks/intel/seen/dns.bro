@load base/frameworks/intel
@load ./where-locations

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	Intel::seen([$indicator=query,
	             $indicator_type=Intel::DOMAIN,
	             $conn=c,
	             $where=DNS::IN_REQUEST]);
	}
