# @TEST-DOC: Crafted pcap causing crashes due to mail not initialized.
# @TEST-EXEC: zeek -b -r $TRACES/pop3/bad-list-retr-crafted.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff analyzer_debug.log

@load frameworks/analyzer/debug-logging.zeek
@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/pop3

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_POP3, 110/tcp);
	}
