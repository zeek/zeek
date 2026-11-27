# @TEST-DOC: Each DNP3 port is registered for the analyzer of its transport: the TCP port for DNP3_TCP, the UDP port for DNP3_UDP.
#
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/protocols/dnp3

event zeek_init() &priority=-5
	{
	print "DNP3_TCP", Analyzer::registered_ports(Analyzer::ANALYZER_DNP3_TCP);
	print "DNP3_UDP", Analyzer::registered_ports(Analyzer::ANALYZER_DNP3_UDP);
	}
