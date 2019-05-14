# @TEST-EXEC: zeek -r $TRACES/empty.trace >output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: zeek -r $TRACES/empty.trace -f "port 42" >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: zeek -r $TRACES/mixed-vlan-mpls.trace PacketFilter::restricted_filter="vlan" >>output
# @TEST-EXEC: cat packet_filter.log >>output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log
# 
# The order in the output of enable_auto_protocol_capture_filters isn't
# stable, for reasons not clear. We canonify it first.
# @TEST-EXEC: zeek -r $TRACES/empty.trace PacketFilter::enable_auto_protocol_capture_filters=T
# @TEST-EXEC: cat packet_filter.log | zeek-cut filter | sed 's#[()]##g' | tr ' ' '\n' | sort | uniq -c | awk '{print $1, $2}' >output2
# @TEST-EXEC: btest-diff output2

