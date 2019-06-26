# @TEST-EXEC: zeek -r $TRACES/tunnels/gtp/gtp3_false_gtp.pcap
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: test ! -e tunnel.log

# The fact that udp port 2152 on only one side already qualifies for GTP
# increases the risk for false positives, see this trace. This is not a
# GTP packet, but a DNS packet which just happens to use port 2152
