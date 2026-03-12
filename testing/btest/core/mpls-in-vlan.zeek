# @TEST-EXEC: zeek -C -r $TRACES/mpls-in-vlan.pcap
# @TEST-EXEC: btest-diff conn.log
