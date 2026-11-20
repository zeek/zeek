# @TEST-DOC: Tests basic functionality of the L2TP analyzer
#
# @TEST-EXEC: zeek -r $TRACES/nb6-l2tp.pcap
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: btest-diff-cut -m http.log
