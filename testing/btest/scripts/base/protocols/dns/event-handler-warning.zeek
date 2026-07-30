# Check that warnings are for events that will not be raised

# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

@load base/protocols/dns

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
	{
	print "";
	}

event dns_EDNS_ecs(c: connection, msg: dns_msg, opt: dns_edns_ecs)
	{
	print "";
	}

event dns_EDNS_tcp_keepalive(c: connection, msg: dns_msg, opt: dns_edns_tcp_keepalive)
	{
	print "";
	}

event dns_EDNS_cookie(c: connection, msg: dns_msg, opt: dns_edns_cookie)
	{
	print "";
	}

event dns_TKEY(c: connection, msg: dns_msg, ans: dns_tkey)
	{
	print "";
	}
