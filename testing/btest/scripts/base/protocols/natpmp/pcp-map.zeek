# @TEST-DOC: Basic testing for PCP success, error, and timeout cases.
#
# @TEST_REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -r $TRACES/nat/pcp-map.pcap
# @TEST-EXEC: btest-diff-cut -m -d uid service conn.log
# @TEST-EXEC: btest-diff-cut -m nat-traversal.log

@load base/protocols/conn
@load base/protocols/nat-traversal
