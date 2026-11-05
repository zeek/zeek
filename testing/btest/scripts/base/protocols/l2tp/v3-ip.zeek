# @TEST-DOC: Tests receiving L2TPv3 over IP
#
# @TEST-EXEC: zeek -r $TRACES/l2tp/http-over-l2tpv3-ip.pcap
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: btest-diff-cut -m http.log
