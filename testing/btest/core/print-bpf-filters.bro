# @TEST-EXEC: bro -r $TRACES/empty.trace >output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: bro -r $TRACES/empty.trace -f "port 42" >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: bro -r $TRACES/mixed-vlan-mpls.trace PacketFilter::restricted_filter="vlan" >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log
