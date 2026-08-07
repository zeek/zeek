# @TEST-DOC: Tests that receiving Telnet AUTH STATUS before NAME doesn't result in crashes
# @TEST-EXEC: zeek -b -r $TRACES/telnet-auth-missing-name.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_TELNET, 21/tcp);
	}

event authentication_accepted(name: string, c: connection)
	{
	# If the name is missing, this would crash.
	print to_lower(name);
	}
