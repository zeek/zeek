# @TEST-DOC: Test Zeek parsing a trace file through the PostgreSQL analyzer.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-select-now.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff output

@load base/protocols/postgresql

event PostgreSQL::authentication_request(c: connection, identifier: count, data: string) {
	print "authentication_request", c$uid, identifier, data;
}

event PostgreSQL::authentication_response(c: connection, data: string) {
	print "authentication_response", c$uid, data;
}

event PostgreSQL::authentication_ok(c: connection) {
	print "authentication_ok", c$uid;
}
