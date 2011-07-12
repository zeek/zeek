# @TEST-EXEC: bro -C -r $TRACES/mixed-vlan-mpls.trace protocols/conn
# @TEST-EXEC: btest-diff conn.log
