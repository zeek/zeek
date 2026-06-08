# @TEST-DOC: An SNMP varbind OID carrying an overlong subidentifier (eleven bytes, shift count 70) is rejected with a weird instead of triggering uint64 shift UB. Pcap built with the adjacent scapy script.
#
# @TEST-EXEC: zeek -r $TRACES/snmp/snmp-oid-subidentifier-too-long.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/snmp
