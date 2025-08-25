##! Base DNS analysis script which tracks and logs DNS queries along with
##! their responses.

@load base/utils/queue
@load ./consts
@load base/protocols/conn/removal-hooks

module DNS;

export {
	## The DNS logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the DNS log.
	type Info: record {
		## The earliest time at which a DNS protocol message over the
		## associated connection is observed.
		ts:            time               &log;
		## A unique identifier of the connection over which DNS messages
		## are being transferred.
		uid:           conn_uid           &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:            conn_id            &log;
		## The transport layer protocol of the connection.
		proto:         transport_proto    &log;
		## A 16-bit identifier assigned by the program that generated
		## the DNS query.  Also used in responses to match up replies to
		## outstanding queries.
		trans_id:      count              &log &optional;
		## Round trip time for the query and response. This indicates
		## the delay between when the request was seen until the
		## answer started.
		rtt:           interval           &log &optional;
		## The domain name that is the subject of the DNS query.
		query:         string             &log &optional;
		## The QCLASS value specifying the class of the query.
		qclass:        count              &log &optional;
		## A descriptive name for the class of the query.
		qclass_name:   string             &log &optional;
		## A QTYPE value specifying the type of the query.
		qtype:         count              &log &optional;
		## A descriptive name for the type of the query.
		qtype_name:    string             &log &optional;
		## The response code value in DNS response messages.
		rcode:         count              &log &optional;
		## A descriptive name for the response code value.
		rcode_name:    string             &log &optional;
		## The Authoritative Answer bit for response messages specifies
		## that the responding name server is an authority for the
		## domain name in the question section.
		AA:            bool               &log &default=F;
		## The Truncation bit specifies that the message was truncated.
		TC:            bool               &log &default=F;
		## The Recursion Desired bit in a request message indicates that
		## the client wants recursive service for this query.
		RD:            bool               &log &default=F;
		## The Recursion Available bit in a response message indicates
		## that the name server supports recursive queries.
		RA:            bool               &log &default=F;
		## A reserved field that is zero in queries and responses unless
		## using DNSSEC. This field represents the 3-bit Z field using
		## the specification from RFC 1035.
		Z:             count              &log &default=0;
		## The set of resource descriptions in the query answer.
		answers:       vector of string   &log &optional;
		## The caching intervals of the associated RRs described by the
		## *answers* field.
		TTLs:          vector of interval &log &optional;
		## The DNS query was rejected by the server.
		rejected:      bool               &log &default=F;

		## The total number of resource records in a reply message's
		## answer section.
		total_answers: count           &optional;
		## The total number of resource records in a reply message's
		## answer, authority, and additional sections.
		total_replies: count           &optional;

		## Whether the full DNS query has been seen.
		saw_query: bool                &default=F;
		## Whether the full DNS reply has been seen.
		saw_reply: bool                &default=F;
	};

	## An event that can be handled to access the :zeek:type:`DNS::Info`
	## record as it is sent to the logging framework.
	global log_dns: event(rec: Info);

	## This is called by the specific dns_*_reply events with a "reply"
	## which may not represent the full data available from the resource
	## record, but it's generally considered a summarization of the
	## responses.
	##
	## c: The connection record for which to fill in DNS reply data.
	##
	## msg: The DNS message header information for the response.
	##
	## ans: The general information of a RR response.
	##
	## reply: The specific response information according to RR type/class.
	global do_reply: hook(c: connection, msg: dns_msg, ans: dns_answer, reply: string);

	## A hook that is called whenever a session is being set.
	## This can be used if additional initialization logic needs to happen
	## when creating a new session value.
	##
	## c: The connection involved in the new session.
	##
	## msg: The DNS message header information.
	##
	## is_query: Indicator for if this is being called for a query or a response.
	global set_session: hook(c: connection, msg: dns_msg, is_query: bool);

	## Yields a queue of :zeek:see:`DNS::Info` objects for a given
	## DNS message query/transaction ID.
	type PendingMessages: table[count] of Queue::Queue;

	## Give up trying to match pending DNS queries or replies for a given
	## query/transaction ID once this number of unmatched queries or replies
	## is reached (this shouldn't happen unless either the DNS server/resolver
	## is broken, Zeek is not seeing all the DNS traffic, or an AXFR query
	## response is ongoing).
	option max_pending_msgs = 50;

	## Give up trying to match pending DNS queries or replies across all
	## query/transaction IDs once there is at least one unmatched query or
	## reply across this number of different query IDs.
	option max_pending_query_ids = 50;

	## A record type which tracks the status of DNS queries for a given
	## :zeek:type:`connection`.
	type State: record {
		## A single query that hasn't been matched with a response yet.
		## Note this is maintained separate from the *pending_queries*
		## field solely for performance reasons -- it's possible that
		## *pending_queries* contains further queries for which a response
		## has not yet been seen, even for the same transaction ID.
		pending_query: Info &optional;

		## Indexed by query id, returns Info record corresponding to
		## queries that haven't been matched with a response yet.
		pending_queries: PendingMessages &optional;

		## Indexed by query id, returns Info record corresponding to
		## replies that haven't been matched with a query yet.
		pending_replies: PendingMessages &optional;
	};

	## DNS finalization hook.  Remaining DNS info may get logged when it's called.
	global finalize_dns: Conn::RemovalHook;
}


redef record connection += {
	dns:       Info  &optional;
	dns_state: State &optional;
};

const ports = { 53/udp, 53/tcp, 137/udp, 5353/udp, 5355/udp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(DNS::LOG, Log::Stream($columns=Info, $ev=log_dns, $path="dns", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNS, ports);
	}

function new_session(c: connection, trans_id: count): Info
	{
	local info: Info;
	info$ts       = network_time();
	info$id       = c$id;
	info$uid      = c$uid;
	info$proto    = get_port_transport_proto(c$id$resp_p);
	info$trans_id = trans_id;
	return info;
	}

function log_unmatched_msgs_queue(q: Queue::Queue)
	{
	local infos: vector of Info;
	Queue::get_vector(q, infos);

	for ( i in infos )
		{
		Log::write(DNS::LOG, infos[i]);
		}
	}

function log_unmatched_msgs(msgs: PendingMessages)
	{
	for ( _, q in msgs )
		{
		log_unmatched_msgs_queue(q);
		}

	clear_table(msgs);
	}

function enqueue_new_msg(msgs: PendingMessages, id: count, msg: Info)
	{
	if ( id !in msgs )
		{
		if ( |msgs| > max_pending_query_ids )
			{
			# Throw away all unmatched on assumption they'll never be matched.
			log_unmatched_msgs(msgs);
			}

		msgs[id] = Queue::init();
		}
	else
		{
		if ( Queue::len(msgs[id]) > max_pending_msgs )
			{
			log_unmatched_msgs_queue(msgs[id]);
			# Throw away all unmatched on assumption they'll never be matched.
			msgs[id] = Queue::init();
			}
		}

	Queue::put(msgs[id], msg);
	}

function pop_msg(msgs: PendingMessages, id: count): Info
	{
	local rval: Info = Queue::get(msgs[id]);

	if ( Queue::len(msgs[id]) == 0 )
		delete msgs[id];

	return rval;
	}

hook set_session(c: connection, msg: dns_msg, is_query: bool) &priority=5
	{
	if ( ! c?$dns_state )
		{
		local state: State;
		c$dns_state = state;
		Conn::register_removal_hook(c, finalize_dns);
		}

	if ( is_query )
		{
		if ( c$dns_state?$pending_replies && msg$id in c$dns_state$pending_replies &&
		     Queue::len(c$dns_state$pending_replies[msg$id]) > 0 )
			{
			# Match this DNS query w/ what's at head of pending reply queue.
			c$dns = pop_msg(c$dns_state$pending_replies, msg$id);
			}
		else
			{
			# Create a new DNS session and put it in the query queue so
			# we can wait for a matching reply.
			c$dns = new_session(c, msg$id);

			if( ! c$dns_state?$pending_query )
				c$dns_state$pending_query = c$dns;
			else
				{
				if( !c$dns_state?$pending_queries )
					c$dns_state$pending_queries = table();

				enqueue_new_msg(c$dns_state$pending_queries, msg$id, c$dns);
				}
			}
		}
	else
		{
		if ( c$dns_state?$pending_query && c$dns_state$pending_query$trans_id == msg$id )
			{
			c$dns = c$dns_state$pending_query;
			delete c$dns_state$pending_query;

			if ( c$dns_state?$pending_queries )
				{
				# Popping off an arbitrary, unpaired query to set as the
				# new fastpath is necessary in order to preserve the overall
				# queuing order of any pending queries that may share a
				# transaction ID.  If we didn't fill c$dns_state$pending_query
				# back in, then it's possible a new query would jump ahead in
				# the queue of some other pending query since
				# c$dns_state$pending_query is filled first if available.

				if ( msg$id in c$dns_state$pending_queries &&
				     Queue::len(c$dns_state$pending_queries[msg$id]) > 0 )
					# Prioritize any pending query with matching ID to the one
					# that just got paired with a response.
					c$dns_state$pending_query = pop_msg(c$dns_state$pending_queries, msg$id);
				else
					{
					# Just pick an arbitrary, unpaired query.
					local tid: count &is_assigned;
					local found_one = F;

					for ( trans_id, q in c$dns_state$pending_queries )
						if ( Queue::len(q) > 0 )
							{
							tid = trans_id;
							found_one = T;
							break;
							}

					if ( found_one )
						c$dns_state$pending_query = pop_msg(c$dns_state$pending_queries, tid);
					}
				}
			}
		else if ( c$dns_state?$pending_queries && msg$id in c$dns_state$pending_queries &&
		     Queue::len(c$dns_state$pending_queries[msg$id]) > 0 )
			{
			# Match this DNS reply w/ what's at head of pending query queue.
			c$dns = pop_msg(c$dns_state$pending_queries, msg$id);
			}
		else
			{
			# Create a new DNS session and put it in the reply queue so
			# we can wait for a matching query.
			c$dns = new_session(c, msg$id);

			if( ! c$dns_state?$pending_replies )
				c$dns_state$pending_replies = table();

			enqueue_new_msg(c$dns_state$pending_replies, msg$id, c$dns);
			}
		}

	if ( ! is_query )
		{
		c$dns$rcode = msg$rcode;
		c$dns$rcode_name = base_errors[msg$rcode];

		if ( ! c$dns?$total_answers )
			c$dns$total_answers = msg$num_answers;

		if ( ! c$dns?$total_replies )
			c$dns$total_replies = msg$num_answers + msg$num_addl + msg$num_auth;

		if ( msg$rcode != 0 && msg$num_queries == 0 )
			c$dns$rejected = T;
		}
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=5
	{
	if ( msg$opcode != 0 )
		# Currently only standard queries are tracked.
		return;

	hook set_session(c, msg, ! msg$QR);
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

	if ( ans$answer_type == DNS_ANS )
		{
		if ( ! c$dns?$query )
			c$dns$query = ans$query;

		c$dns$AA    = msg$AA;
		c$dns$RA    = msg$RA;

		if ( ! c$dns?$rtt )
			{
			c$dns$rtt = network_time() - c$dns$ts;
			# This could mean that only a reply was seen since
			# we assume there must be some passage of time between
			# request and response.
			if ( c$dns$rtt == 0secs )
				delete c$dns$rtt;
			}

		if ( reply != "" )
			{
			if ( ! c$dns?$answers )
				c$dns$answers = vector();
			c$dns$answers += reply;

			if ( ! c$dns?$TTLs )
				c$dns$TTLs = vector();
			c$dns$TTLs += ans$TTL;
			}
		}
	}

event dns_end(c: connection, msg: dns_msg) &priority=5
	{
	if ( ! c?$dns )
		return;

	if ( msg$QR )
		c$dns$saw_reply = T;
	else
		c$dns$saw_query = T;
	}

event dns_end(c: connection, msg: dns_msg) &priority=-5
	{
	if ( c?$dns && c$dns$saw_reply && c$dns$saw_query )
		{
		Log::write(DNS::LOG, c$dns);
		delete c$dns;
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	if ( msg$opcode != 0 )
		# Currently only standard queries are tracked.
		return;

	c$dns$RD          = msg$RD;
	c$dns$TC          = msg$TC;
	c$dns$qclass      = qclass;
	c$dns$qclass_name = classes[qclass];
	c$dns$qtype       = qtype;
	c$dns$qtype_name  = query_types[qtype];
	c$dns$Z           = msg$Z;

	# Decode netbios name queries
	# Note: I'm ignoring the name type for now.  Not sure if this should be
	#       worked into the query/response in some fashion.
	if ( c$id$resp_p == 137/udp )
		{
		local decoded_query = decode_netbios_name(query);

		if ( |decoded_query| != 0 )
			query = decoded_query;

		if ( c$dns$qtype_name == "SRV" )
			{
			# The SRV RFC used the ID used for NetBios Status RRs.
			# So if this is NetBios Name Service we name it correctly.
			c$dns$qtype_name = "NBSTAT";
			}
		}
	c$dns$query = query;
	}


event dns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("<unknown type=%s>", ans$qtype));
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("%s", a));
	}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) &priority=5
	{
	local txt_strings: string = "";

	for ( i in strs )
		{
		if ( i > 0 )
			txt_strings += " ";

		txt_strings += fmt("TXT %d %s", |strs[i]|, strs[i]);
		}

	hook DNS::do_reply(c, msg, ans, txt_strings);
	}

event dns_SPF_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) &priority=5
	{
	local spf_strings: string = "";

	for ( i in strs )
		{
		if ( i > 0 )
			spf_strings += " ";

		spf_strings += fmt("SPF %d %s", |strs[i]|, strs[i]);
		}

	hook DNS::do_reply(c, msg, ans, spf_strings);
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("%s", a));
	}

event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("%s", a));
	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, soa$mname);
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "");
	}

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, target);
	}

event dns_NAPTR_reply(c: connection, msg: dns_msg, ans: dns_answer, naptr: dns_naptr_rr) &priority=5
	{
	# Just encode all the fields for NAPTR RR in the reply string.
	local tmp = "";

	if ( |naptr$regexp| > 0 )
		tmp += naptr$regexp;

	if ( |naptr$replacement| > 0 )
		{
		if ( |tmp| > 0 )
			tmp += " ";

		tmp += naptr$replacement;
		}

	local r = fmt("NAPTR %s %s %s %s %s", naptr$order, naptr$preference, naptr$flags, naptr$service, tmp);

	hook DNS::do_reply(c, msg, ans, r);
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
# event dns_EDNS_ecs(c: connection, msg: dns_msg, opt: dns_edns_ecs)
#	{
#
#	}
#
#event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
#	{
#
#	}

event dns_RRSIG(c: connection, msg: dns_msg, ans: dns_answer, rrsig: dns_rrsig_rr) &priority=5
	{
	local s: string;
	s = fmt("RRSIG %s %s", rrsig$type_covered,
	        rrsig$signer_name == "" ? "<Root>" : rrsig$signer_name);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_DNSKEY(c: connection, msg: dns_msg, ans: dns_answer, dnskey: dns_dnskey_rr) &priority=5
	{
	local s: string;
	s = fmt("DNSKEY %s", dnskey$algorithm);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_NSEC(c: connection, msg: dns_msg, ans: dns_answer, next_name: string, bitmaps: string_vec) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("NSEC %s %s", ans$query, next_name));
	}

event dns_NSEC3(c: connection, msg: dns_msg, ans: dns_answer, nsec3: dns_nsec3_rr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "NSEC3");
	}

event dns_NSEC3PARAM(c: connection, msg: dns_msg, ans: dns_answer, nsec3param: dns_nsec3param_rr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "NSEC3PARAM");
	}

event dns_DS(c: connection, msg: dns_msg, ans: dns_answer, ds: dns_ds_rr) &priority=5
	{
	local s: string;
	s = fmt("DS %s %s", ds$algorithm, ds$digest_type);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_BINDS(c: connection, msg: dns_msg, ans: dns_answer, binds: dns_binds_rr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "BIND9 signing signal");
	}

event dns_SSHFP(c: connection, msg: dns_msg, ans: dns_answer, algo: count, fptype: count, fingerprint: string) &priority=5
	{
	local s: string;
	s = fmt("SSHFP: %s", bytestring_to_hexstr(fingerprint));
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_LOC(c: connection, msg: dns_msg, ans: dns_answer, loc: dns_loc_rr) &priority=5
	{
	local s: string;
	s = fmt("LOC:  %d %d %d", loc$size, loc$horiz_pre, loc$vert_pre);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	if ( c?$dns )
		c$dns$rejected = T;
	}

hook finalize_dns(c: connection)
	{
	if ( ! c?$dns_state )
		return;

	# If Zeek is expiring state, we should go ahead and log all unmatched
	# queries and replies now.
	if( c$dns_state?$pending_query )
		Log::write(DNS::LOG, c$dns_state$pending_query);

	if( c$dns_state?$pending_queries )
		log_unmatched_msgs(c$dns_state$pending_queries);

	if( c$dns_state?$pending_replies )
		log_unmatched_msgs(c$dns_state$pending_replies);
	}
