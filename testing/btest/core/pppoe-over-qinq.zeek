# Disable test temporarily - see GH-4547
# @TEST-REQUIRES: ! have-spicy-ssl

# @TEST-EXEC: zeek -r $TRACES/pppoe-over-qinq.pcap
# @TEST-EXEC: btest-diff conn.log
