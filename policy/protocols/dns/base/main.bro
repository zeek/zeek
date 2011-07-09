@load protocols/dns/base/consts

module DNS;

export {
	redef enum Log::ID += { DNS };
	
	type Info: record {
		ts:            time            &log;
		uid:           string          &log;
		id:            conn_id         &log;
		proto:         transport_proto &log;
		trans_id:      count           &log &optional;
		query:         string          &log &optional;
		qclass:        count           &log &optional;
		qclass_name:   string          &log &optional;
		qtype:         count           &log &optional;
		qtype_name:    string          &log &optional;
		rcode:         count           &log &optional;
		rcode_name:    string          &log &optional;
		QR:            bool            &log &default=F;
		AA:            bool            &log &default=F;
		TC:            bool            &log &default=F;
		RD:            bool            &log &default=F;
		RA:            bool            &log &default=F;
		Z:             count           &log &default=0;
		TTL:           interval        &log &optional;
		answers:       set[string]     &log &optional;
		
		## This value indicates if this request/response pair is ready to be logged.
		ready:         bool            &default=F;
		total_answers: count           &optional;
		total_replies: count           &optional;
	};
	
	type State: record {
		## Indexed by query id, returns Info record corresponding to
		## query/response which haven't completed yet.
		pending: table[count] of Info &optional;
		
		## This is the list of DNS responses that have completed based on the
		## number of responses declared and the number received.  The contents
		## of the set are transaction IDs.
		finished_answers: set[count] &optional;
	};
	
	global log_dns: event(rec: Info);
	
	## This is called by the specific dns_*_reply events with a "reply" which
	## may not represent the full data available from the resource record, but 
	## it's generally considered a summarization of the response(s).
	# TODO: Weirdly enough, if I define this, the locally defined script layer
	#       event won't trigger any of it's handlers.
	#global do_reply: event(c: connection, msg: dns_msg, ans: dns_answer, reply: string);
}

redef record connection += {
	dns:       Info  &optional;
	dns_state: State &optional;
};

# DPD configuration.
redef capture_filters += { 
	["dns"] = "port 53",
	["mdns"] = "udp and port 5353",
	["llmns"] = "udp and port 5355",
	["netbios-ns"] = "udp port 137", 
};

global dns_ports = { 53/udp, 53/tcp, 137/udp, 5353/udp, 5355/udp } &redef;
redef dpd_config += { [ANALYZER_DNS] = [$ports = dns_ports] };

global dns_udp_ports = { 53/udp, 137/udp, 5353/udp, 5355/udp } &redef;
global dns_tcp_ports = { 53/tcp } &redef;
redef dpd_config += { [ANALYZER_DNS_UDP_BINPAC] = [$ports = dns_udp_ports] };
redef dpd_config += { [ANALYZER_DNS_TCP_BINPAC] = [$ports = dns_tcp_ports] };

event bro_init() &priority=5
	{
	Log::create_stream(DNS, [$columns=Info, $ev=log_dns]);
	}

function new_session(c: connection, trans_id: count): Info
	{
	if ( ! c?$dns_state )
		{
		local state: State;
		state$pending=table();
		state$finished_answers=set();
		c$dns_state = state;
		}
	
	local info: Info;
	info$ts       = network_time();
	info$id       = c$id;
	info$uid      = c$uid;
	info$proto    = get_conn_transport_proto(c$id);
	info$trans_id = trans_id;
	return info;
	}

function set_session(c: connection, msg: dns_msg, is_query: bool)
	{
	if ( ! c?$dns_state || msg$id !in c$dns_state$pending )
		c$dns_state$pending[msg$id] = new_session(c, msg$id);
		
	c$dns = c$dns_state$pending[msg$id];

	c$dns$rcode = msg$rcode;
	c$dns$rcode_name = base_errors[msg$rcode];
	
	if ( ! is_query )
		{
		if ( ! c$dns?$total_answers )
			c$dns$total_answers = msg$num_answers;
		
		if ( c$dns?$total_replies && 
		     c$dns$total_replies != msg$num_answers + msg$num_addl + msg$num_auth )
			{
			event conn_weird("dns_changed_number_of_responses", c, 
			                      fmt("The declared number of responses changed from %d to %d", 
			                          c$dns$total_replies,
			                          msg$num_answers + msg$num_addl + msg$num_auth));
			}
		else
			{
			# Store the total number of responses expected from the first reply.
			c$dns$total_replies = msg$num_answers + msg$num_addl + msg$num_auth;
			}
		}
	}
	
event do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=5
	{
	set_session(c, msg, F);

	c$dns$AA    = msg$AA;
	c$dns$RA    = msg$RA;
	c$dns$TTL   = ans$TTL;

	if ( ans$answer_type == DNS_ANS )
		{
		if ( msg$id in c$dns_state$finished_answers )
			event conn_weird("dns_reply_seen_after_done", c, "");
		
		if ( reply != "" )
			{
			if ( ! c$dns?$answers )
				c$dns$answers = set();
			add c$dns$answers[reply];
			}
		
		if ( c$dns?$answers && |c$dns$answers| == c$dns$total_answers )
			{
			add c$dns_state$finished_answers[c$dns$trans_id];
			# Indicate this request/reply pair is ready to be logged.
			c$dns$ready = T;
			}
		}
	}
	
event do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=-5
	{
	if ( c$dns$ready )
		{
		Log::write(DNS, c$dns);
		add c$dns_state$finished_answers[c$dns$trans_id];
		# This record is logged and no longer pending.
		delete c$dns_state$pending[c$dns$trans_id];
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	set_session(c, msg, T);
	
	c$dns$RD          = msg$RD;
	c$dns$TC          = msg$TC;
	c$dns$qclass      = qclass;
	c$dns$qclass_name = classes[qclass];
	c$dns$qtype       = qtype;
	c$dns$qtype_name  = query_types[qtype];
	
	# Decode netbios name queries
	# Note: I'm ignoring the name type for now.  Not sure if this should be 
	#       worked into the query/response in some fashion.
	if ( c$id$resp_p == 137/udp )
		query = decode_netbios_name(query);
	c$dns$query    = query;
	
	c$dns$Z = msg$Z;
	}
	
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	event do_reply(c, msg, ans, fmt("%s", a));
	}
	
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string) &priority=5
	{
	event do_reply(c, msg, ans, str);
	}
	
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr, 
                     astr: string) &priority=5
	{
	# TODO: What should we do with astr?
	event do_reply(c, msg, ans, fmt("%s", a));
	}
	
event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	event do_reply(c, msg, ans, name);
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	event do_reply(c, msg, ans, name);
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count) &priority=5
	{
	event do_reply(c, msg, ans, name);
	}
	
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	event do_reply(c, msg, ans, name);
	}
	
event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa) &priority=5
	{
	event do_reply(c, msg, ans, soa$mname);
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	event do_reply(c, msg, ans, "");
	}
	
event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	event do_reply(c, msg, ans, "");
	}

# TODO: figure out how to handle these
#event dns_EDNS(c: connection, msg: dns_msg, ans: dns_answer)
#	{
#	
#	}
#
#event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
#	{
#	
#	}
#
#event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
#	{
#	
#	}


event dns_rejected(c: connection, msg: dns_msg,
                   query: string, qtype: count, qclass: count) &priority=5
	{
	set_session(c, msg, F);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( ! c?$dns_state )
		return;
		
	# If Bro is expiring state, we should go ahead and log all unlogged 
	# request/response pairs now.
	for ( trans_id in c$dns_state$pending )
		Log::write(DNS, c$dns_state$pending[trans_id]);
	}
	
