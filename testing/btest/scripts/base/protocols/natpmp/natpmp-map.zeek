# @TEST-DOC: Basic testing for NAT-PMP success, error, and timeout cases.
#
# @TEST_REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -r $TRACES/nat/natpmp-map.pcap
# @TEST-EXEC: btest-diff-cut -m -d uid service conn.log
# @TEST-EXEC: btest-diff-cut -m nat-traversal.log
