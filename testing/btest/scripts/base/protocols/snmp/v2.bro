# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv2_get.pcap %INPUT $SCRIPTS/snmp-test.bro >out1
# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv2_get_bulk.pcap %INPUT $SCRIPTS/snmp-test.bro >out2
# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv2_get_next.pcap %INPUT $SCRIPTS/snmp-test.bro >out3

# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2
# @TEST-EXEC: btest-diff out3

@load base/protocols/snmp
