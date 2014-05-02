##! Enables analysis of SNMP datagrams.

module SNMP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		duration: interval &log &default=0secs;

		version: string &log;
		community: string &log &optional;

		get_requests:      count &log &default=0;
		get_bulk_requests: count &log &default=0;
		get_responses:     count &log &default=0;

		set_requests: count &log &default=0;

		display_string: string &log &optional;
		up_since: time &log &optional;
	};

	redef record connection += {
		snmp: SNMP::Info &optional;
	};

	global log_snmp: event(rec: Info);
}

const ports = { 161/udp, 162/udp };
redef likely_server_ports += { ports };

const version_map = {
	[0] = "1",
	[1] = "2c",
	[3] = "3",
};

event bro_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SNMP, ports);
	Log::create_stream(SNMP::LOG, [$columns=SNMP::Info, $ev=log_snmp]);
	}

function init_state(c: connection, h: SNMP::Header): Info
	{
	if ( ! c?$snmp )
		{
		c$snmp = Info($ts=network_time(), 
		              $uid=c$uid, $id=c$id,
		              $version=version_map[h$version]);
		}

	local s = c$snmp;
	if ( ! s?$community )
		{
		if ( h?$v1 )
			s$community = h$v1$community;
		if ( h?$v2 )
			s$community = h$v2$community;
		}

	s$duration = network_time() - s$ts;
	return s;
	}


event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$snmp )
		Log::write(LOG, c$snmp);
	}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	for ( i in pdu$bindings )
		{
		++s$get_requests;
		}
	}

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU) &priority=5
	{
	local s = init_state(c, header);
	for ( i in pdu$bindings )
		{
		++s$get_bulk_requests;
		}
	}

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	for ( i in pdu$bindings )
		{
		++s$get_requests;
		}
	}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);

	for ( i in pdu$bindings )
		{
		++s$get_responses;

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
	for ( i in pdu$bindings )
		{
		++s$set_requests;
		}
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

event snmp_unknown_header_version(c: connection, is_orig: bool, version: count) &priority=5
	{
	}
