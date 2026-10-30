# @TEST-DOC: Tests that idle L2TPv3 session state is expired by the V3 session timer
#
# @TEST-EXEC: zeek -r $TRACES/l2tp/l2tpv3-session-timeout-udp.pcap
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log
