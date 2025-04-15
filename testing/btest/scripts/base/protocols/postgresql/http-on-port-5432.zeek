# @TEST-DOC: Test rejecting wrong protocol.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -Cr ${TRACES}/postgresql/http-on-port-5432.pcap %INPUT >output
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p history service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m < analyzer_debug.log > analyzer.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -r 's,(.*) \(/[^\)]+\),\1 (...),'" btest-diff analyzer.cut
# @TEST-EXEC: test ! -f postgresql.log

@load frameworks/analyzer/debug-logging.zeek
@load base/protocols/conn
@load base/protocols/postgresql
