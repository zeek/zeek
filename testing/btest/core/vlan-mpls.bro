# @TEST-EXEC: bro -C -r $TRACES/mixed-vlan-mpls.trace conn
# @TEST-EXEC: btest-diff conn.log
