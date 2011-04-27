@load functions

module DNS;

redef enum Log::ID += { DNS };

export {
	type Info: record {
		ts:            time            &log;
		id:            conn_id         &log;
		proto:         transport_proto &log;
		trans_id:      count           &log &optional;
		query:         string          &log &optional;
		qtype:         count           &log &optional;
		qtype_name:    string          &log &optional;
		qclass:        count           &log &optional;
		rcode:         count           &log &optional;
		QR:            bool            &log &default=F;
		Z:             bool            &log &default=F;
		AA:            bool            &log &default=F;
		RD:            bool            &log &default=F;
		RA:            bool            &log &default=F;
		TC:            bool            &log &default=F;
		TTL:           interval        &log &optional;
		nxdomain:      bool            &log &default=F;
		replies:       set[string]     &log &optional;
		
		total_answers:    count    &optional;
	};
	
	type State: record {
		## When activity was last seen for this session.
		last_active:  time &optional;

		## Indexed by query id, returns Info record corresponding to
		## query/response which haven't completed yet.
		pending: table[count] of Info &optional;
	};
	
	global log_dns: event(rec: Info);
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

event bro_init()
	{
	Log::create_stream(DNS, [$columns=Info, $ev=log_dns]);
	}

function new_session(c: connection, trans_id: count): Info
	{
	if ( ! c?$dns_state )
		{
		local state: State;
		state$last_active=network_time();
		state$pending=table();
		c$dns_state = state;
		}
	
	local info: Info;
	info$ts       = network_time();
	info$id       = c$id;
	info$proto    = get_conn_transport_proto(c$id);
	info$trans_id = trans_id;
	return info;
	}

function set_session(c: connection, msg: dns_msg, is_query: bool)
	{
	if ( ! c?$dns_state || msg$id !in c$dns_state$pending )
		c$dns_state$pending[msg$id] = new_session(c, msg$id);
		
	c$dns = c$dns_state$pending[msg$id];

	c$dns_state$last_active=network_time();
	c$dns$rcode = msg$rcode;
	
	if ( ! is_query )
		{
		if ( c$dns?$total_answers && 
		     c$dns$total_answers != msg$num_answers + msg$num_addl + msg$num_auth )
			{
			#print "the total number of answers changed midstream on a dns response.";
			#print info;
			#print msg;
			}
		else
			{
			c$dns$total_answers = msg$num_answers + msg$num_addl + msg$num_auth;
			}
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	set_session(c, msg, T);
	
	c$dns$RD         = msg$RD;
	c$dns$TC         = msg$TC;
	c$dns$qtype      = qtype;
	c$dns$qtype_name = query_types[qtype];
	c$dns$qclass     = qclass;
	
	# Decode netbios name queries
	# Note: I'm ignoring the name type for now.  Not sure if this should be 
	#       worked into the query/response in some fashion.
	if ( c$id$resp_p == 137/udp )
		query = decode_netbios_name(query);
		
	c$dns$query    = query;
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[fmt("%s", a)];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}
	
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[str];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}
	
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr, 
                     astr: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[fmt("%s", a)];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}
	
event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[name];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[name];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}


event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[name];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}
	
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[name];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}
	
event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
	{
	set_session(c, msg, F);
	
	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$replies )
			c$dns$replies = set();
		add c$dns$replies[soa$mname];
		c$dns$RA    = msg$RA;
		c$dns$TTL   = ans$TTL;
		}
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	set_session(c, msg, F);
	}
	
event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer)
	{
	set_session(c, msg, F);
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
                   query: string, qtype: count, qclass: count)
	{
	set_session(c, msg, F);
	
	c$dns$nxdomain = T;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( ! c?$dns_state )
		return;
		
	# If Bro is expiring state, we should go ahead and log all unlogged 
	# request/response pairs now.
	for ( pair in c$dns_state$pending )
		Log::write(DNS, c$dns_state$pending[pair]);
	}