# $Id: hot.bro 7057 2010-07-19 23:22:19Z vern $

@load site
@load port-name
@load notice
@load terminate-connection

module Hot;

export {
	# True if it should be considered a spoofing attack if a connection has
	# the same local net for source and destination.
	const same_local_net_is_spoof = F &redef;

	const allow_spoof_services = {
		110/tcp,	# pop-3
		139/tcp,	# netbios-ssn
	} &redef;

	# Indexed by source address and destination address.
	const allow_pairs: set[addr, addr] &redef;

	const hot_srcs: table[addr] of string = {
		#	[ph33r.the.eleet.com] = "kidz",
	} &redef;

	const hot_dsts: table[addr] of string = {
		[206.101.197.226] = "ILOVEYOU worm destination",
	} &redef;

	const allow_services = {
		ssh, http, gopher, ident, smtp, 20/tcp,
		53/udp,		# DNS queries
		123/udp,	# NTP
	} &redef;

	const allow_services_to: set[addr, port] &redef;
	const allow_services_from: set[addr, port] &redef;
	const allow_service_pairs: set[addr, addr, port] &redef;

	const flag_successful_service: table[port] of string = {
		[[31337/tcp]] = "popular backdoors",
	} &redef;

	const flag_successful_inbound_service: table[port] of string = {
		[1524/tcp] = "popular backdoor, but with false hits outbound",
	} &redef;

	const terminate_successful_inbound_service: table[port] of string &redef;

	const flag_rejected_service: table[port] of string &redef;

	# Different values to hand to check_hot() at different stages in
	# a connection's lifetime.
	const CONN_ATTEMPTED = 1;
	const CONN_ESTABLISHED = 2;
	const APPL_ESTABLISHED = 3;
	const CONN_FINISHED = 4;
	const CONN_REJECTED = 5;
	const CONN_TIMEOUT = 6;
	const CONN_REUSED = 7;

	global check_hot: function(c: connection, state: count): bool;
	global check_spoof: function(c: connection): bool;
}

# An internal function used by check_hot.
function do_hot_check(c: connection, a: addr, t: table[addr] of string)
	{
	if ( a in t )
		{
		++c$hot;
		local hot_msg = fmt("<%s>", t[a]);
		append_addl(c, hot_msg);
		}
	}

function check_spoof(c: connection): bool
	{
	local orig = c$id$orig_h;
	local resp = c$id$resp_h;
	local service = c$id$resp_p;

	if ( is_local_addr(orig) && is_local_addr(resp) &&
	     service !in allow_spoof_services )
		{
		if ( c$id$orig_p == service && orig == resp )
			event conn_weird("Land_attack", c);

		if ( same_local_net_is_spoof )
			++c$hot;
		}

	return c$hot != 0;
	}

function check_hot(c: connection, state: count): bool
	{
	local id = c$id;
	local service = id$resp_p;

	if ( service in allow_services || "ftp-data" in c$service )
		return F;

	if ( state == CONN_ATTEMPTED )
		check_spoof(c);

	else if ( state == CONN_REJECTED )
		{
		check_spoof(c);

		if ( service in flag_rejected_service )
			++c$hot;
		}

	else if ( state == CONN_ESTABLISHED )
		{
		check_spoof(c);

		local inbound = is_local_addr(id$resp_h);

		if ( (service in flag_successful_service ||
		      (inbound &&
		       service in flag_successful_inbound_service)) &&
		     ([id$resp_h, id$resp_p] !in allow_services_to || 
		      [id$orig_h, id$resp_p] !in allow_services_from) )
			{
			if ( inbound &&
			     service in terminate_successful_inbound_service )
				TerminateConnection::terminate_connection(c);

			++c$hot;
			if ( service in flag_successful_service )
				append_addl(c, flag_successful_service[service]);
			else
				append_addl(c, flag_successful_inbound_service[service]);
			}
		}

	else if ( state == APPL_ESTABLISHED ||
		  ((state == CONN_FINISHED || state == CONN_TIMEOUT ||
		    state == CONN_REUSED) &&
		   service != telnet && c$orig$size > 0 && c$resp$size > 0) )
		{
		# Connection established and has a non-trivial size.
		local orig = c$id$orig_h;
		local resp = c$id$resp_h;

		if ( [resp, service] in allow_services_to ||
		     [orig, service] in allow_services_from ||
		     [orig, resp, service] in allow_service_pairs ||
		     [orig, resp] in allow_pairs )
			return F;

		do_hot_check(c, resp, hot_srcs);
		do_hot_check(c, resp, hot_dsts);
		}

	return c$hot != 0;
	}
