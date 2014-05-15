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

hook DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=5
	{
	if ( msg$opcode != 0 )
		# Currently only standard queries are tracked.
		return;

	if ( ! msg$QR )
		# This is weird: the inquirer must also be providing answers in
		# the request, which is not what we want to track.
		return;

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
	}
