# $Id:$

@load dns
@load anon

module DNS;

redef rewriting_dns_trace = T;

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	if ( get_conn_transport_proto(c$id) == udp )
		rewrite_dns_message(c, is_orig, msg, len);
	}

event dns_request(c: connection, msg: dns_msg, query: string,
			qtype: count, qclass: count)
	{
	if ( get_conn_transport_proto(c$id) == udp )
		rewrite_dns_request(c, anonymize_host(query),
					msg, qtype, qclass);
	}

event dns_end(c: connection, msg: dns_msg)
	{
	if ( get_conn_transport_proto(c$id) == udp )
		rewrite_dns_end(c, T);
	}

event dns_query_reply(c: connection, msg: dns_msg, query: string,
			qtype: count, qclass: count)
	{
	rewrite_dns_reply_question(c, msg, anonymize_host(query),
					qtype, qclass);
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	ans$query = anonymize_host(ans$query);
	rewrite_dns_A_reply(c, msg, ans, anonymize_address(a, c$id));
	}

#### FIXME: ANONYMIZE!
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer,
			a: addr, astr: string)
	{
	ans$query = anonymize_host(ans$query);
	astr = "::";
	a = anonymize_address(a, c$id);
	rewrite_dns_AAAA_reply(c, msg, ans, a, astr);
	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	ans$query = anonymize_host(ans$query);
	rewrite_dns_NS_reply(c, msg, ans, anonymize_host(name));
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer,
			name: string)
	{
	ans$query = anonymize_host(ans$query);
	rewrite_dns_CNAME_reply(c, msg, ans, anonymize_host(name));
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer,
			name: string, preference: count)
	{
	ans$query = anonymize_host(ans$query);
	rewrite_dns_MX_reply(c, msg, ans, anonymize_host(name), preference);
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	ans$query = anonymize_host(ans$query);
	rewrite_dns_PTR_reply(c, msg, ans, anonymize_host(name));
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
	{
	soa$mname = anonymize_host(soa$mname);
	soa$rname = anonymize_host(soa$rname);
	ans$query = anonymize_host(ans$query);
	rewrite_dns_SOA_reply(c, msg, ans, soa);
	}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer,
			str: string)
	{
	str = anonymize_string(str);
	ans$query = anonymize_host(ans$query);
	rewrite_dns_TXT_reply(c, msg, ans, str);
	}

event dns_EDNS_addl (c: connection, msg: dns_msg, ans: dns_edns_additional)
	{
	rewrite_dns_EDNS_addl(c, msg, ans);
	}

event dns_rejected(c: connection, msg: dns_msg, query: string,
			qtype: count, qclass: count)
	{
	#### Hmmm, this is probably not right - we are going to have to look
	# at the question type to determine how to anonymize this.
	rewrite_dns_reply_question(c, msg, anonymize_host(query),
					qtype, qclass);
	}
