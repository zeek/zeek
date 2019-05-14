# @TEST-EXEC: zeek -C -r $TRACES/mpls-in-vlan.trace
# @TEST-EXEC: btest-diff conn.log
