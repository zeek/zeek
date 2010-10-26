@load global-ext
@load dns

type dns_ext_session_info: record {
	id: conn_id;
	ts: time;
	trans_id: count;
	query: string;
	qtype: count;
	qclass: count;
	total_answers: count &default=0;
	rcode: count &default = 65536;
	QR: bool &default=F;
	Z:  bool &default=F;
	AA: bool &default=F;
	RD: bool &default=F;
	RA: bool &default=F;
	TC: bool &default=F;
	TTL: interval &default=0secs;
	replies: set[string];
};

# Define the generic dns-ext event that can be handled from other scripts
global dns_ext: event(id: conn_id, di: dns_ext_session_info);

module DNS;

export {
	# Follow this example to define domains that you would consider "local".
	# This is primarily useful if you are monitoring authoritative nameservers,
	# but also useful for any zones that *should* be pointing at your 
	# network.
	# e.g.
	#const local_domains = /(^|\.)(osu|ohio-state)\.edu$/ | 
	#                      /(^|\.)akamai(tech)?\.net$/ &redef;
	const local_domains = /(^|\.)akamai(tech)?\.net$/ &redef;
	
	redef enum Notice += { 
		# Raised when a non-local name is found to be pointing at a local host.
		#  This only works appropriately when all of your authoritative DNS 
		#  servers are located in your "local_nets".
		DNSExternalName, 
		};
}


global dns_sessions_ext: table[addr, addr, count] of dns_ext_session_info;

# This doesn't work with live traffic yet.
# It's waiting for support to dynamically construct pattern variables at init time.
#global dns_suffix_regex = build_regex(local_domains, "(^|\.)~~$");
#event bro_init()
#	{
#	local i: count = 0;
#	local tmp_pattern: pattern;
#	for ( d in local_domains )
#		{
#		tmp_pattern = string_to_pattern( fmt("=%s@", d), T );
#		
#		if ( i == 0 )
#			pat = tmp_pattern;
#		else
#			pat = merge_pattern(tmp_pattern, pat);
#		++i;
#		}
#	}

event expire_DNS_session_ext(orig: addr, resp: addr, trans_id: count)
	{
	if ( [orig, resp, trans_id] in dns_sessions_ext )
		{
		local session = dns_sessions[orig, resp, trans_id];
		local session_ext = dns_sessions_ext[orig, resp, trans_id];
		
		event dns_ext(session_ext$id, session_ext);
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	if ( [orig, resp, msg$id] !in dns_sessions_ext )
		{
		session_ext$id = c$id;
		session_ext$trans_id = msg$id;
		session_ext$ts = network_time();
		session_ext$RD = msg$RD;
		session_ext$TC = msg$TC;
		session_ext$qtype = qtype;
		session_ext$qclass = qclass;
		session_ext$query = query;
		local strings: set[string] = set();
		session_ext$replies = strings;
		dns_sessions_ext[orig, resp, msg$id] = session_ext;
		
		# This needs to expire before the original dns.bro script expires the 
		# the data from the dns_session variable.
		schedule 14secs { expire_DNS_session_ext(orig, resp, msg$id) };
		}
	}


event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		add session_ext$replies[fmt("%s",a)];
		session_ext$RA = msg$RA;
		session_ext$TTL = ans$TTL;
		session_ext$rcode = msg$rcode;
		}
	
	# Check for out of place domain names
	if ( is_local_addr(a) &&            # referring to a local host
	     !is_local_addr(c$id$resp_h) && # response from a remote host
	     local_domains !in ans$query )  # drop known names
		{
		NOTICE([$note=DNSExternalName,
		        $msg=fmt("%s is pointing to a local host - %s.", ans$query, a),
		        $conn=c]);
		}
	}
	
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[str];
		}
	}
	
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr, 
                     astr: string)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[fmt("%s", a)];
		}
	}


event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count)
	{
	local id=c$id;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	
	if ( [id$orig_h, id$resp_h, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[id$orig_h, id$resp_h, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[name];
		}
	}
	
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		add session_ext$replies[name];
		}
	}

event dns_end(c: connection, msg: dns_msg)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local session_ext: dns_ext_session_info;
	
	if ( [orig, resp, msg$id] in dns_sessions_ext )
		{
		session_ext = dns_sessions_ext[orig, resp, msg$id];
		session_ext$rcode = msg$rcode;
		}	
	}
