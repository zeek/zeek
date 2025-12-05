# @TEST-DOC: Test analyzer confirmation event handlers
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/Teredo.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http
@load base/protocols/tunnels

global confirmation_count = 0;
global second_confirmation_count = 0;

module Analyzer;

event my_confirmation_handler(tag: Tag, info: AnalyzerConfirmationInfo)
	{
	++confirmation_count;
	print "handler #1 invoked", tag, confirmation_count;
	if ( info?$c )
		print "  connection:", info$c$id;
	if ( info?$aid )
		print "  analyzer id:", info$aid;
	}

event second_confirmation_handler(tag: Tag, info: AnalyzerConfirmationInfo)
	{
	++second_confirmation_count;
	print "handler #2 invoked", tag, second_confirmation_count;
	if ( info?$c )
		print "  connection:", info$c$id;
	if ( info?$aid )
		print "  analyzer id:", info$aid;
	}

event zeek_init()
	{
	register_confirmation_handler(ANALYZER_HTTP, my_confirmation_handler);
	register_confirmation_handler(ANALYZER_HTTP,
					second_confirmation_handler);
	register_confirmation_handler(PacketAnalyzer::ANALYZER_TEREDO,
					second_confirmation_handler);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "confirmation:", atype;
	}

event zeek_done()
	{
	print fmt("total confirmations via handler: %d/%d",
			confirmation_count, second_confirmation_count);
	}
