# $Id: dns.bro 6724 2009-06-07 09:23:03Z vern $

@load notice
@load weird
@load udp-common
@load dns-info

module DNS;

export {
	# Lookups of hosts in here are flagged ...
	const sensitive_lookup_hosts: set[addr] &redef;

	# ... unless the lookup comes from one of these hosts.
	const okay_to_lookup_sensitive_hosts: set[addr] &redef;

	# Start considering whether we're seeing PTR scanning if we've seen
	# at least this many rejected PTR queries.
	const report_rejected_PTR_thresh = 100 &redef;

	# Generate a PTR_scan event if at any point (once we're above
	# report_rejected_PTR_thresh) we see this many more distinct
	# rejected PTR requests than distinct answered PTR requests.
	const report_rejected_PTR_factor = 2.0 &redef;

	# The following sources are allowed to do PTR scanning.
	const allow_PTR_scans: set[addr] &redef;

	# Annotations that if returned for a PTR lookup actually indicate
	# a rejected query; for example, "illegal-address.lbl.gov".
	const actually_rejected_PTR_anno: set[string] &redef;

	# Hosts allowed to do zone transfers.
	const zone_transfers_okay: set[addr] &redef;

	# Set to false to disable printing to dns.log.
	const logging = T &redef;

	redef enum Notice += {
		SensitiveDNS_Lookup,	# DNS lookup of sensitive hostname/addr
		DNS_PTR_Scan,		# A set of PTR lookups
		DNS_PTR_Scan_Summary,	# Summary of a set of PTR lookups
		ResolverInconsistency,	# DNS answer changed
		ZoneTransfer,		# a DNS zone transfer request was seen

	};

	# This is a list of domains that have a history of providing
	# more RR's in response than they are supposed to.  There is
	# some danger here in that record inconsistancies will not be 
	# identified for these domains...
	const bad_domain_resp: set[string] &redef;

	# Same idea, except that it applies to a list of host names.
	const bad_host_resp: set[string] &redef;

	# Turn resolver consistancy checking on/off.
	const resolver_consist_check = F &redef;

	# Should queries be checked against 'bad' domains?
	const check_domain_list = T;

	# List of 'bad' domains.
	const hostile_domain_list: set[string] &redef;

	# Used for PTR scan detection.  Exported so their timeouts can be
	# adjusted.
	global distinct_PTR_requests:
		table[addr, string] of count &default = 0 &write_expire = 5 min;
	global distinct_rejected_PTR_requests:
		table[addr] of count &default = 0 &write_expire = 5 min;
	global distinct_answered_PTR_requests:
		table[addr] of count &default = 0 &write_expire = 5 min;
}

redef capture_filters += { 
	["dns"] = "port 53",
	["netbios-ns"] = "udp port 137", 
};

# DPM configuration.
global dns_ports = { 53/udp, 53/tcp, 137/udp } &redef;
redef dpd_config += { [ANALYZER_DNS] = [$ports = dns_ports] };

global dns_udp_ports = { 53/udp, 137/udp } &redef;
global dns_tcp_ports = { 53/tcp } &redef;
redef dpd_config += { [ANALYZER_DNS_UDP_BINPAC] = [$ports = dns_udp_ports] };
redef dpd_config += { [ANALYZER_DNS_TCP_BINPAC] = [$ports = dns_tcp_ports] };

# Default handling for peculiarities in DNS analysis.  You can redef these
# again in your site-specific script if you want different behavior.
redef Weird::weird_action += {
	["DNS_AAAA_neg_length"]	= Weird::WEIRD_FILE,
	["DNS_Conn_count_too_large"]	= Weird::WEIRD_FILE,
	["DNS_NAME_too_long"]	= Weird::WEIRD_FILE,
	["DNS_RR_bad_length"]	= Weird::WEIRD_FILE,
	["DNS_RR_length_mismatch"]	= Weird::WEIRD_FILE,
	["DNS_RR_unknown_type"]	= Weird::WEIRD_FILE,
	["DNS_label_forward_compress_offset"]	= Weird::WEIRD_FILE,
	["DNS_label_len_gt_name_len"]	= Weird::WEIRD_FILE,
	["DNS_label_len_gt_pkt"]	= Weird::WEIRD_FILE,
	["DNS_label_too_long"]	= Weird::WEIRD_FILE,
	["DNS_name_too_long"]	= Weird::WEIRD_FILE,
	["DNS_truncated_RR_rdlength_lt_len"]	= Weird::WEIRD_FILE,
	["DNS_truncated_ans_too_short"]	= Weird::WEIRD_FILE,
	["DNS_truncated_len_lt_hdr_len"]	= Weird::WEIRD_FILE,
	["DNS_truncated_quest_too_short"]	= Weird::WEIRD_FILE,
};

type dns_session_info: record {
	id: count;
	is_zone_transfer: bool;
	last_active: time;	# when we last saw activity

	# Indexed by query id, returns string annotation corresponding to
	# queries for which no answer seen yet.
	pending_queries: table[count] of string;
};

# Indexed by client and server.
global dns_sessions: table[addr, addr, count] of dns_session_info;
global num_dns_sessions = 0;

const PTR_pattern = /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.in-addr\.arpa/;

# Keeps track of for which addresses we processed a PTR_scan event.
global did_PTR_scan_event: table[addr] of count &default = 0;

# The following definitions relate to tracking when DNS records
# change and whether they do so in a consistent fashion.
type dns_response_record: record {
	dns_name: string;	# domain name in question
	dns_type: count;	# type of query
	num_resp: count;	# number of responses
	resp_count: count;	# how many responses have been registered
	addrs: set[addr];	# addresses in response
};

global dns_history: table[string, count, count] of dns_response_record;

global did_zone_transfer_notice: table[addr] of count &default = 0;

# Sample known irregular domains.
redef bad_domain_resp += { "instacontent.net", "mirror-image.net", };

# Sample hostile domains.
redef hostile_domain_list += { "undernet.org", "afraid.org", };

global dns_log : file;

event bro_init()
	{
	if ( logging )
		dns_log = open_log_file("dns");
	}

event remove_name(name: string, qtype: count, id: count)
	{
	if ( [name, qtype, id] in dns_history )
		{
		# We need to remove the dns_history record and the assosciated
		# dns_consistency_info records.

		local drr = dns_history[name, qtype, id];
		local a: addr;

		for ( a in drr$addrs )
			delete drr$addrs[a];

		delete dns_history[name, qtype, id];
		}
	else if ( logging )
		print dns_log, fmt("ERROR in history session removal: %s/%d doesn't exist", name, qtype);
	}

# Returns the second-level domain, so for example an argument of "a.b.c.d"
# returns "c.d".
function second_level_domain(name: string): string
	{
	local split_on_dots = split(name, /\./);
	local num_dots = length(split_on_dots);

	if ( num_dots <= 1 )
		return name;

	return fmt("%s.%s", split_on_dots[num_dots-1], split_on_dots[num_dots]);
	}

function insert_name(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	local drr: dns_response_record;

	if ( [ans$query, ans$qtype, msg$id] !in dns_history )
		{ # add record
		drr$dns_name = ans$query;
		drr$dns_type = ans$qtype;

		# Here we modified the expected number of addresses to allow
		# for the number of answer RR's along with the provided
		# additional RR's.
		drr$num_resp = msg$num_answers+msg$num_addl;
		drr$resp_count = 0;
		add drr$addrs[a];

		dns_history[ans$query, ans$qtype, msg$id] = drr;

		if ( ans$TTL < 0 sec )
			# Strangely enough, the spec allows this,
			# though it's hard to see why!  But because
			# of that, we don't generate a Weird, we
			# just change the TTL to 0.
			ans$TTL = 0 sec;

		# Check the TTL, but allow a smidgen of skew to avoid
		# possible race conditions.
		schedule ans$TTL + 1 sec
			{ remove_name(ans$query, ans$qtype, msg$id) };
		}
	else
		{ # extract record and do some counting
		drr = dns_history[ans$query, ans$qtype, msg$id];

		# In some broken records, the number of reported records is 0.
		# This makes the test below fail, to 'fix' set to 1 ...
		if ( drr$num_resp == 0 )
			drr$num_resp = 1;

		# Check if we have filled in the expected number of responses
		# already - it should be > current responder count to allow
		# for resolver timeouts.  Addresses are only added if they
		# are not already prsent.  This comes at a slight performance
		# cost.
		if ( a !in drr$addrs ) 
			{
			add drr$addrs[a];
			++drr$resp_count;
			dns_history[ans$query, ans$qtype, msg$id]=drr;
			}

		if ( drr$num_resp >= drr$resp_count )
			return;

		if ( second_level_domain(ans$query) in bad_domain_resp )
			return;

		if ( ans$query in bad_host_resp )
			return;

		# Too many responses to the request, or some other
		# inconsistency has been introduced.

		NOTICE([$note=ResolverInconsistency, $conn=c,
			$msg=fmt("address inconsistency for %s, %s", ans$query, a),
			$dst=a]);
		}
	}

event expire_DNS_session(orig: addr, resp: addr, trans_id: count)
	{
	if ( [orig, resp, trans_id] in dns_sessions )
		{
		local session = dns_sessions[orig, resp, trans_id];
		local last_active = session$last_active;
		if ( network_time() > last_active + dns_session_timeout ||
		     done_with_network )
			{
			# Flush out any pending requests.
			if ( logging )
				{
				for ( query in session$pending_queries )
					print dns_log, fmt("%0.6f #%d %s",
							network_time(), session$id,
							session$pending_queries[query]);

				print dns_log, fmt("%.06f #%d finish",
						network_time(), session$id);
				}

			delete dns_sessions[orig, resp, trans_id];
			}

		else
			schedule dns_session_timeout {
				expire_DNS_session(orig, resp, trans_id)
			};
		}
	}

function lookup_DNS_session(c: connection, trans_id: count): dns_session_info
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;

	if ( [orig, resp, trans_id] !in dns_sessions )
		{
		local session: dns_session_info;
		session$id = ++num_dns_sessions;
		session$last_active = network_time();
		session$is_zone_transfer = F;

		if ( logging )
			print dns_log, fmt("%.06f #%d %s start",
				c$start_time, session$id, id_string(id));

		dns_sessions[orig, resp, trans_id] = session;

		schedule 15 sec { expire_DNS_session(orig, resp, trans_id) };

		append_addl(c, fmt("#%d", session$id));

		return session;
		}

	else
		return dns_sessions[orig, resp, trans_id];
	}

event sensitive_addr_lookup(c: connection, a: addr, is_query: bool)
	{
	local orig = c$id$orig_h;
	local resp = c$id$resp_h;
	local holding = 0;

	if ( orig in okay_to_lookup_sensitive_hosts )
		return;

	local session_id: string;
	if ( [orig, resp, holding] in dns_sessions )
		session_id = fmt("#%d", dns_sessions[orig, resp, holding]$id);
	else
		session_id = "#?";

	local id = fmt("%s > %s (%s)", orig, resp, session_id);

	if ( is_query )
		NOTICE([$note=SensitiveDNS_Lookup, $conn=c,
			$msg=fmt("%s PTR lookup of %s", id, a),
			$sub="PTR lookup"]);
	else
		NOTICE([$note=SensitiveDNS_Lookup, $conn=c,
			$msg=fmt("%s name lookup of %s", id, a),
			$sub="name lookup"]);
	}

function DNS_query_annotation(c: connection, msg: dns_msg, query: string,
				qtype: count, is_zone_xfer: bool): string
	{
	local anno: string;

	if ( (qtype == PTR || qtype == ANY) && query == PTR_pattern )
		{
		# convert PTR text to more readable form.
		local a = ptr_name_to_addr(query);
		if ( a in sensitive_lookup_hosts && ! is_zone_xfer )
			event sensitive_addr_lookup(c, a, T);

		anno = fmt("?%s %As", query_types[qtype], a);
		}
	else
		anno = fmt("%s %s", query_types[qtype], query);

	if ( ! is_zone_xfer &&
	     (msg$num_answers > 0 || msg$num_auth > 0 || msg$num_addl > 0) )
		anno = fmt("%s <query addl = %d/%d/%d>", anno,
			msg$num_answers, msg$num_auth, msg$num_addl);

	return anno;
	}


event dns_zone_transfer_request(c: connection, session: dns_session_info,
				msg: dns_msg, query: string)
	{
	session$is_zone_transfer = T;

	if ( ! is_tcp_port(c$id$orig_p) )
		event conn_weird("UDP_zone_transfer", c);

	local src = c$id$orig_h;
	if ( src !in zone_transfers_okay &&
	     ++did_zone_transfer_notice[src] == 1 )
		{
		NOTICE([$note=ZoneTransfer, $src=src, $conn=c,
			$msg=fmt("transfer of %s requested by %s", query, src)]);
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local session = lookup_DNS_session(c, msg$id);
	local anno = DNS_query_annotation(c, msg, query, qtype, F);

	local report = fmt("%.06f #%d %s", network_time(), session$id, c$id$orig_h);
	local q: string;

	if ( query_types[qtype] == "AXFR" )
		{
		event dns_zone_transfer_request(c, session, msg, query);

		q = DNS_query_annotation(c, msg, query, qtype, T);
		report = fmt("%s ?%s", report, q);
		}
	else
		report = fmt("%s <query ?%s> %s Trunc:%s Recurs:%s",
			report, query_types[qtype], query, msg$TC, msg$RD);

	if ( logging )
		print dns_log, fmt("%s", report);

	# Check to see if this is a host or MX lookup for a designated
	# hostile domain.
	if ( check_domain_list &&
	     (query_types[qtype] == "A" || query_types[qtype] == "MX") &&
	     second_level_domain(query) in hostile_domain_list )
		{
		NOTICE([$note=SensitiveDNS_Lookup, $conn=c,
			$msg=fmt("%s suspicious domain lookup: %s", id, query)]);
		}

	session$pending_queries[msg$id] = anno;
	session$last_active = network_time();
	}

event dns_rejected(c: connection, msg: dns_msg,
			query: string, qtype: count, qclass: count)
	{
	local session = lookup_DNS_session(c, msg$id);
	local code = DNS_code_types[msg$rcode];
	local id = msg$id;

	if ( id in session$pending_queries )
		{
		if ( logging )
			print dns_log, fmt("%.06f #%d %s %s", network_time(),
						session$id,
						session$pending_queries[id],
						code);

		delete session$pending_queries[id];
		}

	else if ( logging )
		{
		if ( c$start_time == network_time() )
			print dns_log, fmt("%.06f #%d [?%s] %s", network_time(),
						session$id, query, code);
		else
			print dns_log, fmt("%.06f #%d %s", network_time(),
						session$id, code);
		}
	}

event PTR_scan_summary(src: addr)
	{
	NOTICE([$note=DNS_PTR_Scan_Summary, $src=src,
		$msg=fmt("%s totaled %d/%d un/successful PTR lookups", src,
			distinct_rejected_PTR_requests[src],
			distinct_answered_PTR_requests[src]),
		$sub="final summary"]);
	}

event PTR_scan(src: addr)
	{
	++did_PTR_scan_event[src];

	if ( src !in allow_PTR_scans && src !in okay_to_lookup_sensitive_hosts )
		{
		NOTICE([$note=DNS_PTR_Scan, $src=src,
			$msg=fmt("%s has made %d/%d un/successful PTR lookups",
				src, distinct_rejected_PTR_requests[src],
				distinct_answered_PTR_requests[src]),
			$sub="scan detected"]);

		schedule 1 day { PTR_scan_summary(src) };
		}
	}

function check_PTR_scan(src: addr)
	{
	if ( src !in did_PTR_scan_event &&
	     distinct_rejected_PTR_requests[src] >=
	     distinct_answered_PTR_requests[src] * report_rejected_PTR_factor )
		event PTR_scan(src);
	}

function DNS_answer(c: connection, msg: dns_msg,
			ans: dns_answer, annotation: string)
	{
	local is_answer = ans$answer_type == DNS_ANS;
	local session = lookup_DNS_session(c, msg$id);
	local report =
		fmt("%.06f #%d %s", network_time(), session$id, c$id$orig_h);
	local id = msg$id;
	local query: string;

	if ( id in session$pending_queries )
		{
		query = fmt("%s = <ans %s>", session$pending_queries[id],
				query_types[ans$qtype]);
		delete session$pending_queries[id];
		report = fmt("%s %s", report, query);
		}

	else if ( session$is_zone_transfer )
		{ # need to provide the query directly.
		query = fmt("<ans %s>", query_types[ans$qtype]);
		report = fmt("%s ?%s", report, query);
		}

	else
		{
		# No corresponding query.  This can happen if it's
		# already been deleted because we've already processed
		# an answer to it; or if the session itself was timed
		# out prior to this answer being generated.  In the
		# first case, we don't want to provide the query again;
		# in the second, we do.  We can determine that we're
		# likely in the second case if either (1) this session
		# was just now created, or (2) we're now processing the
		# sole answer to the original query.
		#
		# However, for now we punt.
		#
		#	if ( c$start_time == network_time() ||
		#	     (is_answer && msg$num_answers == 1) )
		#		{
		#		query = DNS_query_annotation(c, msg, ans$query, ans$qtype, F);
		#		report = fmt("%s [?%s]", report, query);
		#		}
		#	else
		#		query = "";

		query = fmt("<ans %s>", query_types[ans$qtype]);
		report = fmt("%s %s", report, query);
		}

	# Append a bunch of additional annotation.
	report = fmt("%s %s RCode:%s AA=%s TR=%s %s/%s/%s/%s",
		report, annotation, base_error[msg$rcode], msg$AA, msg$TC,
		msg$num_queries, msg$num_answers, msg$num_auth, msg$num_addl );

	local src = c$id$orig_h;

	if ( msg$rcode != 0 )
		{
		if ( /\?(PTR|\*.*in-addr).*/ in query )
			##### should check for private address
			{
			if ( ++distinct_PTR_requests[src, query] == 1 &&
			     ++distinct_rejected_PTR_requests[src] >=
			       report_rejected_PTR_thresh )
				check_PTR_scan(src);
			}

		report = fmt("%s %s", report, DNS_code_types[msg$rcode]);
		}

	else if ( is_answer )
		{
		if ( /\?(PTR|\*.*in-addr).*/ in query )
			{
			if ( annotation in actually_rejected_PTR_anno )
				{
				if ( ++distinct_PTR_requests[src, query] == 1 &&
				     ++distinct_rejected_PTR_requests[src] >=
				       report_rejected_PTR_thresh )
					check_PTR_scan(src);
				}
			else
				{
				if ( ++distinct_PTR_requests[src, query] == 1 )
					++distinct_answered_PTR_requests[src];
				}
			}
		}

	if ( logging )
		print dns_log, fmt("%s TTL=%g", report, ans$TTL);

	### Note, DNS_AUTH and DNS_ADDL not processed.

	session$last_active = network_time();
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	if ( a in sensitive_lookup_hosts )
		event sensitive_addr_lookup(c, a, F);

	DNS_answer(c, msg, ans, fmt("%As", a));

	if ( resolver_consist_check )
		insert_name(c, msg, ans, a );

	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	DNS_answer(c, msg, ans, fmt("%s", name));
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	DNS_answer(c, msg, ans, fmt("%s %s", query_types[ans$qtype], name));
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	DNS_answer(c, msg, ans, fmt("%s", name));
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
	{
	DNS_answer(c, msg, ans, fmt("%s", soa$mname));
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
			preference: count)
	{
	DNS_answer(c, msg, ans, fmt("%s/%d", name, preference));
	}

event dns_EDNS(c: connection, msg: dns_msg, ans: dns_answer)
	{
	DNS_answer(c, msg, ans, "<---?--->");
	}


# From here on down we need to modify the way that data is recorded.  The
# standard resource record format is no longer universally applicable in
# that we may see modified structs or some number of value pairs that may take
# more flexability in reporting.

event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
	{
	local session = lookup_DNS_session(c, msg$id);
	local report =
		fmt("%.06f #%d %s", network_time(), session$id, c$id$orig_h);

	if ( ans$is_query == 1 )
		report = fmt("%s <addl_edns ?>", report);
	else
		report = fmt("%s <addl_edns> ", report);

	if ( logging )
		print dns_log, fmt("%s pldsize:%s RCode:%s VER:%s Z:%s",
				report, ans$payload_size,
				base_error[ans$extended_rcode],
				ans$version, edns_zfield[ans$z_field]);
	}

event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
	{
	local session = lookup_DNS_session(c, msg$id);
	local report =
		fmt("%.06f #%d %s", network_time(), session$id, c$id$orig_h);

	# Error handling with this is a little odd: number collision with EDNS.
	# We set the collided value to the first private space number.  gross.
	local trans_error_num = (ans$rr_error == 16) ?  3842 : ans$rr_error;

	if ( ans$is_query == 1 )
		report = fmt("%s <addl_tsig ?> ", report);
	else
		report = fmt("%s <addl_tsig> ", report);

	if ( logging )
		print dns_log, fmt("%s name:%s alg:%s origID:%s RCode:%s",
				report, ans$query, ans$alg_name,
				ans$orig_id, base_error[trans_error_num]);
	}
