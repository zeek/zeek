# @TEST-EXEC: zeek -C -r $TRACES/mixed-vlan-mpls.trace
# @TEST-EXEC: btest-diff conn.log
