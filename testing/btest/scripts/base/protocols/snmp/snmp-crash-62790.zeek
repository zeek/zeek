# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmp-crash-62790.pcap %INPUT $SCRIPTS/snmp-test.zeek >out1

# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff snmp.log

@load base/protocols/snmp
