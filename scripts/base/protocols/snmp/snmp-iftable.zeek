@load ./main

module SNMP::IfTable;

export {
	redef enum Log::ID += { LOG_IfTable };

	type IfEntry: record {
		# Timestamp of first packet containing data for this line of the IfTable
		ts: time &log &default=network_time();
		## The unique ID for the connection.
		uid: string &log;
		## The connection's 5-tuple of addresses/ports (ports inherently
		## include transport protocol information)
		id: conn_id &log;
		oidindex: int;
		ifIndex: int &log &optional;
		ifDescr: string &log &optional;
		ifType: int &log &optional;
		ifMtu: int &log &optional;
		ifSpeed: count &log &optional;
		ifPhysAddress: string &log &optional;
		ifInOctets: count &log &optional;
		ifInUcastPkts: count &log &optional;
		ifInNUcastPkts: count &log &optional;
		ifInDiscards: count &log &optional;
		ifInErrors: count &log &optional;
		ifInUnknownProtos: count &log &optional;
		ifOutOctets: count &log &optional;
		ifOutUcastPkts: count &log &optional;
		ifOutNUcastPkts: count &log &optional;
		ifOutDiscards: count &log &optional;
		ifOutErrors: count &log &optional;
	};
}

global expire_ifentry: function(data: table[int] of IfEntry, idx: int): interval;

redef record SNMP::Info += {
	ifTable: table[int] of IfEntry &default=table() &read_expire=10secs &expire_func=expire_ifentry;
};

function expire_ifentry(t: table[int] of IfEntry, idx: int): interval
	{
	Log::write(LOG_IfTable, t[idx]);

	return 0secs;
	}

event zeek_init()
	{
	Log::create_stream(LOG_IfTable, Log::Stream($columns=IfEntry, $path="snmp_iftable"));
	}

function init_ifentry(c: connection, index: int, flush: bool): IfEntry
	{
	if ( index in c$snmp$ifTable )
		if ( flush )
			Log::write(LOG_IfTable, c$snmp$ifTable[index]);
		else
			return c$snmp$ifTable[index];

	local entry = IfEntry($oidindex = index, $uid=c$uid, $id=c$id);
	c$snmp$ifTable[index] = entry;
	return entry;
	}

function ParseIfTable(c: connection, b: SNMP::Binding)
	{
	# OID has to be checked before
	# table index
	local oid_part = sub_bytes(b$oid, 19, -1);

	local last_dot = rfind_str(oid_part, ".");
	if ( last_dot == -1 )
		return;

	local split_oid = str_split_indices(oid_part, vector(0, int_to_count(last_dot), int_to_count(last_dot)+1));
	if ( |split_oid| != 3 )
		return;

	if ( ! is_num(split_oid[2]) )
		return;

	local column_id = split_oid[0];
	local index = to_int(split_oid[2]);

	local entry = init_ifentry(c, index, column_id == "1");

	switch ( column_id )
		{
		case "1": # ifIndex
			if ( b$value?$signed )
				entry$ifIndex = b$value$signed;
			break;
		case "2": # ifdescr
			if ( b$value?$octets )
				entry$ifDescr = b$value$octets;
			break;
		case "3": # ifType
			if ( b$value?$signed )
				entry$ifType = b$value$signed;
			break;
		case "4": # ifMtu
			if ( b$value?$signed )
				entry$ifMtu = b$value$signed;
			break;
		case "5": # ifSpeed
			if ( b$value?$unsigned )
				entry$ifSpeed = b$value$unsigned;
			break;
		case "6": # ifPhysAddress
			if ( b$value?$octets )
				entry$ifPhysAddress = bytestring_to_hexstr(b$value$octets);
			break;
		case "10": # ifInOctets
			if ( b$value?$unsigned )
				entry$ifInOctets = b$value$unsigned;
			break;
		case "11": # ifInUcastPkts
			if ( b$value?$unsigned )
				entry$ifInUcastPkts = b$value$unsigned;
			break;
		case "12": # ifInNUcastPkts
			if ( b$value?$unsigned )
				entry$ifInNUcastPkts = b$value$unsigned;
			break;
		case "13": # ifInDiscards
			if ( b$value?$unsigned )
				entry$ifInDiscards = b$value$unsigned;
			break;
		case "14": # ifInErrors
			if ( b$value?$unsigned )
				entry$ifInErrors = b$value$unsigned;
			break;
		case "15": # ifInUnknownProtos
			if ( b$value?$unsigned )
				entry$ifInUnknownProtos = b$value$unsigned;
			break;
		case "16": # ifOutOctets
			if ( b$value?$unsigned )
				entry$ifOutOctets = b$value$unsigned;
			break;
		case "17": # ifOutUcastPkts
			if ( b$value?$unsigned )
				entry$ifOutUcastPkts = b$value$unsigned;
			break;
		case "18": # ifOutNUcastPkts
			if ( b$value?$unsigned )
				entry$ifOutNUcastPkts = b$value$unsigned;
			break;
		case "19": # ifOutDiscards
			if ( b$value?$unsigned )
				entry$ifOutDiscards = b$value$unsigned;
			break;
		case "20": # ifOutErrors
			if ( b$value?$unsigned )
				entry$ifOutErrors = b$value$unsigned;
			break;
		default:
			#print "unknown", column_id;
			#print b;
			break;
		}

	#print entry;
	}

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU) &priority=5
	{
	#print "request", pdu;
	}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	# print header, pdu;
	for ( _, binding in pdu$bindings )
		{
		# ifTable
		if ( sub_bytes(binding$oid, 0, 18) == "1.3.6.1.2.1.2.2.1." )
			ParseIfTable(c, binding);
		}
	}
