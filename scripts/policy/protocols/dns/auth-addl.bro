@load base/protocols/dns/main

redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
	redef record Info += {
		auth:       set[string] &log &optional;
		addl:       set[string] &log &optional;
	};
}

event do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=4
	{
	# The "ready" flag will be set here.  This causes the setting from the 
	# base script to be overridden since the base script will log immediately 
	# after all of the ANS replies have been seen.
	c$dns$ready=F;
	
	if ( ans$answer_type == DNS_AUTH )
		{
		if ( ! c$dns?$auth )
			c$dns$auth = set();
		add c$dns$auth[reply];
		}
	else if ( ans$answer_type == DNS_ADDL )
		{
		if ( ! c$dns?$addl )
			c$dns$addl = set();
		add c$dns$addl[reply];
		}
	
	if ( c$dns?$answers && c$dns?$auth && c$dns?$addl &&
	     c$dns$total_replies == |c$dns$answers| + |c$dns$auth| + |c$dns$addl| )
		{
		# *Now* all replies desired have been seen.
		c$dns$ready = T;
		}
	}
