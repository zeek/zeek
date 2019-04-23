# This tests checks that non-dtls connections to which we attach don't trigger tons of errors.

# @TEST-EXEC: zeek -C -r $TRACES/dns-txt-multiple.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
	const add_ports = { 53/udp };
	Analyzer::register_for_ports(Analyzer::ANALYZER_DTLS, add_ports);
	}

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string)
	{
	print c$id, atype, reason;
	}
