# @TEST-EXEC: zeek -b -r $TRACES/snmp/snmpv2_tables.pcap %INPUT
# @TEST-EXEC: btest-diff snmp_iftable.log

@load base/protocols/snmp
