# @TEST-DOC: Event for name, value pairs in the startup message.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-login-no-sslrequest.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff output

@load base/protocols/postgresql

event PostgreSQL::startup_parameter(c: connection, name: string, value: string) {
	print "startup_parameter", c$uid, name, value;
}
