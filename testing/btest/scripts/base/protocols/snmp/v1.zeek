# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv1_get.pcap %INPUT $SCRIPTS/snmp-test.zeek >out1
# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv1_get_short.pcap %INPUT $SCRIPTS/snmp-test.zeek >out2
# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv1_set.pcap %INPUT $SCRIPTS/snmp-test.zeek >out3
# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv1_trap.pcap %INPUT $SCRIPTS/snmp-test.zeek >out4

# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2
# @TEST-EXEC: btest-diff out3
# @TEST-EXEC: btest-diff out4

@load base/protocols/snmp
