# @TEST-DOC: Tests the L2TPv3 maximum-session-count limit
#
# @TEST-EXEC: zeek -r $TRACES/l2tp/l2tpv3-max-sessions-udp.pcap PacketAnalyzer::L2TP::v3_max_sessions=2
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log
