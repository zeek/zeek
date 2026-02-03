# @TEST-DOC: Basic testing for PCP map operation success, error, and timeout cases.
#
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -r $TRACES/nat/pcp-map.pcap
# @TEST-EXEC: btest-diff-cut -m -d uid service conn.log
# @TEST-EXEC: btest-diff-cut -m nat-traversal.log
