# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv1_get.pcap %INPUT $SCRIPTS/snmp-test.bro >out1
# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv1_get_short.pcap %INPUT $SCRIPTS/snmp-test.bro >out2
# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv1_set.pcap %INPUT $SCRIPTS/snmp-test.bro >out3
# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv1_trap.pcap %INPUT $SCRIPTS/snmp-test.bro >out4

# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2
# @TEST-EXEC: btest-diff out3
# @TEST-EXEC: btest-diff out4

@load base/protocols/snmp
