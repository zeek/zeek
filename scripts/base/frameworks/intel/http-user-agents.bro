
@load base/protocols/http
@load base/frameworks/intel

module HTTP;

export {
	redef enum Intel::Where += { 
		HTTP::IN_HEADER,
		HTTP::IN_REQUEST,
		HTTP::IN_HOST_HEADER,
		HTTP::IN_CONN_EST,
		HTTP::IN_DNS_REQUEST,
	};
}

event connection_established(c: connection)
	{
	Intel::found_in_conn(c, [$host=c$id$orig_h, $where=IN_CONN_EST]);
	Intel::found_in_conn(c, [$host=c$id$resp_h, $where=IN_CONN_EST]);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig && name == "USER-AGENT" )
		Intel::found_in_conn(c, [$str=value,
		                         $str_type=Intel::USER_AGENT,
		                         $where=IN_HEADER]);

	if ( is_orig && name == "HOST" )
		Intel::found_in_conn(c, [$str=value,
		                         $str_type=Intel::DOMAIN,
		                         $where=IN_HOST_HEADER]);
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( c?$http )
		{
		if ( c$http?$user_agent )
			Intel::found_in_conn(c, [$str=c$http$user_agent, 
			                         $str_type=Intel::USER_AGENT, 
			                         $where=IN_HEADER]);

		Intel::found_in_conn(c, [$str=HTTP::build_url(c$http),
		                         $str_type=Intel::URL,
		                         $where=IN_REQUEST]);
		}
	}


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	Intel::found_in_conn(c, [$str=query,
	                         $str_type=Intel::DOMAIN,
	                         $where=IN_DNS_REQUEST]);

	}

event Intel::match_in_conn(c: connection, found: Intel::Found, items: set[Intel::Item])
	{
	print "matched one!";
	for ( i in items )
		{
		print "    " + i$meta$desc;
		}
	}