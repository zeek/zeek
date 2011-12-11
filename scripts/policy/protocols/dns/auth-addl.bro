##! This script adds authoritative and additional responses for the current
##! query to the DNS log.  It can cause severe overhead due to the need
##! for all authoritative and additional responses to have events generated.
##! This script is not recommended for use on heavily loaded links.

@load base/protocols/dns/main

redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
	redef record Info += {
		## Authoritative responses for the query.
		auth:       set[string] &log &optional;
		## Additional responses for the query.
		addl:       set[string] &log &optional;
	};
}

event DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=4
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
