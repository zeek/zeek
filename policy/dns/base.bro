@load functions

module DNS;

redef enum Log::ID += { DNS };

export {
	type Info: record {
		ts:            time        &log;
		id:            conn_id     &log;
		trans_id:      count       &log &optional;
		query:         string      &log &optional;
		qtype:         count       &log &optional;
		qclass:        count       &log &optional;
		rcode:         count       &log &optional;
		QR:            bool        &log &default=F;
		Z:             bool        &log &default=F;
		AA:            bool        &log &default=F;
		RD:            bool        &log &default=F;
		RA:            bool        &log &default=F;
		TC:            bool        &log &default=F;
		TTL:           interval    &log &optional;
		replies:       set[string] &log &optional;
		
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
	["netbios-ns"] = "udp port 137", 
};

global dns_ports = { 53/udp, 53/tcp, 137/udp } &redef;
redef dpd_config += { [ANALYZER_DNS] = [$ports = dns_ports] };

global dns_udp_ports = { 53/udp, 137/udp } &redef;
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
	info$trans_id = trans_id;
	return info;
	}

function set_session(c: connection, msg: dns_msg, is_query: bool)
	{
	local info: Info;
	
	# Set the current $dns value back to it's place in the pending queue.
	if ( c?$dns_state && c?$dns )
		c$dns_state$pending[c$dns$trans_id] = c$dns;
	
	if ( c?$dns_state && msg$id in c$dns_state$pending )
		info = c$dns_state$pending[msg$id];
	else
		{
		info = new_session(c, msg$id);
		c$dns_state$pending[msg$id] = info;
		}
	
	c$dns_state$last_active=network_time();

	info$rcode = msg$rcode;
	if ( ! is_query )
		{
		if ( info?$total_answers && 
		     info$total_answers != msg$num_answers + msg$num_addl + msg$num_auth )
			{
			print "the total number of answers changed midstream on a dns response.";
			print info;
			print msg;
			}
		else
			{
			info$total_answers = msg$num_answers + msg$num_addl + msg$num_auth;
			}
		}
	
	c$dns = info;
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	set_session(c, msg, T);
	
	c$dns$RD       = msg$RD;
	c$dns$TC       = msg$TC;
	c$dns$qtype    = qtype;
	c$dns$qclass   = qclass;
	c$dns$query    = query;
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ! c$dns?$replies )
		c$dns$replies = set();
	add c$dns$replies[fmt("%s", a)];
	c$dns$RA    = msg$RA;
	c$dns$TTL   = ans$TTL;
	}
	
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ! c$dns?$replies )
		c$dns$replies = set();
	add c$dns$replies[str];
	}
	
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr, 
                     astr: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ! c$dns?$replies )
		c$dns$replies = set();
	add c$dns$replies[fmt("%s", a)];
	}


event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ! c$dns?$replies )
		c$dns$replies = set();
	add c$dns$replies[name];
	}
	
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	set_session(c, msg, F);
	
	if ( ! c$dns?$replies )
		c$dns$replies = set();
	add c$dns$replies[name];
	}
	
event dns_rejected(c: connection, msg: dns_msg,
                   query: string, qtype: count, qclass: count)
	{
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