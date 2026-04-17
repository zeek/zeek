# @TEST-DOC: Tests the output from the igmp-conn-log policy script

# @TEST-EXEC: zeek -C -r $TRACES/igmp/home-multicast-short.pcap %INPUT
# @TEST-EXEC: btest-diff igmp_conn.log

@load policy/protocols/igmp/igmp-conn-log
