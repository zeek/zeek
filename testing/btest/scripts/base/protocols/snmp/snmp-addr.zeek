# @TEST-EXEC: zeek -C -b -r $TRACES/snmp/snmpwalk-short.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/snmp

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) {

	for (i in pdu$bindings) {
		local binding = pdu$bindings[i];

		if (binding$value?$address)
			print binding$value$address;
	}

}
