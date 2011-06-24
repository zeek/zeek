# @TEST-REQUIRES: bro -e 'print bro_has_ipv6()' | grep -q T
#
# @TEST-EXEC: bro print-filter >output 2>&1
# @TEST-EXEC: bro tcp print-filter >>output
# @TEST-EXEC: bro tcp print-filter all_packets=F >>output
# @TEST-EXEC: bro -f "port 42" print-filter >>output
# @TEST-EXEC: bro -C -f "port 50343" -r $TRACES/mixed-vlan-mpls.trace tcp
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log
