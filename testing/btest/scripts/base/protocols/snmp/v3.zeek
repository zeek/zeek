# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv3_get_next.pcap %INPUT $SCRIPTS/snmp-test.zeek >out1

# @TEST-EXEC: btest-diff out1

@load base/protocols/snmp
