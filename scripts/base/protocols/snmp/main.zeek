##! Enables analysis and logging of SNMP datagrams.

@load base/protocols/conn/removal-hooks

module SNMP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## Information tracked per SNMP session.
	type Info: record {
		## Timestamp of first packet belonging to the SNMP session.
		ts: time &log;
		## The unique ID for the connection.
		uid: string &log;
		## The connection's 5-tuple of addresses/ports (ports inherently
		## include transport protocol information)
		id: conn_id &log;
		## The amount of time between the first packet belonging to
		## the SNMP session and the latest one seen.
		duration: interval &log &default=0secs;
		## The version of SNMP being used.
		version: string &log;
		## The community string of the first SNMP packet associated with
		## the session.  This is used as part of SNMP's (v1 and v2c)
		## administrative/security framework.  See :rfc:`1157` or :rfc:`1901`.
		community: string &log &optional;

		## The number of variable bindings in GetRequest/GetNextRequest PDUs
		## seen for the session.
		get_requests:      count &log &default=0;
		## The number of variable bindings in GetBulkRequest PDUs seen for
		## the session.
		get_bulk_requests: count &log &default=0;
		## The number of variable bindings in GetResponse/Response PDUs seen
		## for the session.
		get_responses:     count &log &default=0;
		## The number of variable bindings in SetRequest PDUs seen for
		## the session.
		set_requests: count &log &default=0;

		## A system description of the SNMP responder endpoint.
		display_string: string &log &optional;
		## The time at which the SNMP responder endpoint claims it's been
		## up since.
		up_since: time &log &optional;
	};

	## Maps an SNMP version integer to a human readable string.
	const version_map: table[count] of string = {
		[0] = "1",
		[1] = "2c",
		[3] = "3",
	} &redef &default="unknown";

	## Event that can be handled to access the SNMP record as it is sent on
	## to the logging framework.
	global log_snmp: event(rec: Info);

	## SNMP finalization hook.  Remaining SNMP info may get logged when it's called.
	global finalize_snmp: Conn::RemovalHook;
}

redef record connection += {
	snmp: SNMP::Info &optional;
};

const ports = { 161/udp, 162/udp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SNMP, ports);
	Log::create_stream(SNMP::LOG, [$columns=SNMP::Info, $ev=log_snmp, $path="snmp", $policy=log_policy]);
	}

function init_state(c: connection, h: SNMP::Header): Info
	{
	if ( ! c?$snmp )
		{
		c$snmp = Info($ts=network_time(),
		              $uid=c$uid, $id=c$id,
		              $version=version_map[h$version]);
		Conn::register_removal_hook(c, finalize_snmp);
		}

	local s = c$snmp;

	if ( ! s?$community )
		{
		if ( h?$v1 )
			s$community = h$v1$community;
		else if ( h?$v2 )
			s$community = h$v2$community;
		}

	s$duration = network_time() - s$ts;
	return s;
	}

hook finalize_snmp(c: connection)
	{
	if ( c?$snmp )
		Log::write(LOG, c$snmp);
	}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_requests += |pdu$bindings|;
	}

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_bulk_requests += |pdu$bindings|;
	}

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_requests += |pdu$bindings|;
	}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_responses += |pdu$bindings|;

	for ( i in pdu$bindings )
		{
		local binding = pdu$bindings[i];

		if ( binding$oid == "1.3.6.1.2.1.1.1.0" && binding$value?$octets )
			c$snmp$display_string = binding$value$octets;
		else if ( binding$oid == "1.3.6.1.2.1.1.3.0" && binding$value?$unsigned )
			{
			local up_seconds = binding$value$unsigned / 100.0;
			s$up_since = network_time() - double_to_interval(up_seconds);
			}
		}
	}

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$set_requests += |pdu$bindings|;
	}

event snmp_trap(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::TrapPDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_inform_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_trapV2(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_report(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_unknown_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count) &priority=5
	{
	init_state(c, header);
	}

event snmp_unknown_scoped_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count) &priority=5
	{
	init_state(c, header);
	}

event snmp_encrypted_pdu(c: connection, is_orig: bool, header: SNMP::Header) &priority=5
	{
	init_state(c, header);
	}

#event snmp_unknown_header_version(c: connection, is_orig: bool, version: count) &priority=5
#	{
#	}
