# @TEST-DOC: Test the parameter status event.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-login-no-sslrequest.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff output

@load base/protocols/postgresql

event PostgreSQL::parameter_status(c: connection, name: string, value: string) {
	print "parameter_status", c$uid, name, value;
}
