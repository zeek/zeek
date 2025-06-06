# @TEST-DOC: Test Zeek parsing a trace file through the PostgreSQL analyzer.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-select-now.pcap %INPUT >output
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m < postgresql.log > postgresql.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: btest-diff postgresql.cut

@load base/protocols/conn
@load base/protocols/postgresql
