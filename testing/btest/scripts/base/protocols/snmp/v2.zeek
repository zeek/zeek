# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv2_get.pcap %INPUT $SCRIPTS/snmp-test.zeek >out1
# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv2_get_bulk.pcap %INPUT $SCRIPTS/snmp-test.zeek >out2
# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv2_get_next.pcap %INPUT $SCRIPTS/snmp-test.zeek >out3

# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2
# @TEST-EXEC: btest-diff out3

@load base/protocols/snmp
