# @TEST-DOC: Test that SSLRequest is recognized and ssl.log exists
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-aws-ssl-disable.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m < postgresql.log > postgresql.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: btest-diff postgresql.cut
# @TEST-EXEC: test ! -f ssl.log

@load base/protocols/conn
@load base/protocols/postgresql
@load base/protocols/ssl
