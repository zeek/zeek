# @TEST-EXEC: bro -r $TRACES/empty.trace -e '' >output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: bro -r $TRACES/empty.trace PacketFilter::all_packets=F >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: bro -r $TRACES/empty.trace -f "port 42" -e '' >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: bro -r $TRACES/empty.trace -C -f "port 56730" -r $TRACES/mixed-vlan-mpls.trace >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log
