# @TEST-EXEC: bro -C -r $TRACES/mixed-vlan-mpls.trace tcp
# @TEST-EXEC: btest-diff conn.log
