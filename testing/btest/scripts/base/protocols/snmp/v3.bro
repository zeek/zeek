# @TEST-EXEC: bro -b -r $TRACES/snmp/snmpv3_get_next.pcap %INPUT $SCRIPTS/snmp-test.bro >out1

# @TEST-EXEC: btest-diff out1

@load base/protocols/snmp
