# @TEST-DOC: Startup message triggering integer overflow

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -Cr ${TRACES}/postgresql/bad-backend-message-1.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m < analyzer.log > analyzer.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -r 's,(.*) \(/[^\)]+\),\1 (...),'" btest-diff analyzer.cut
# @TEST-EXEC: test ! -f reporter.log

@load base/protocols/conn
@load base/protocols/postgresql
