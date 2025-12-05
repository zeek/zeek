# @TEST-DOC: Test analyzer confirmation callbacks
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/Teredo.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http
@load base/protocols/tunnels

global confirmation_count = 0;
global second_confirmation_count = 0;

module Analyzer;

function my_confirmation_callback(tag: Tag, info: AnalyzerConfirmationInfo)
	{
	++confirmation_count;
	print "callback #1 invoked", tag, confirmation_count;
	if ( info?$c )
		print "  connection:", info$c$id;
	if ( info?$aid )
		print "  analyzer id:", info$aid;
	}

function second_confirmation_callback(tag: Tag, info: AnalyzerConfirmationInfo)
	{
	++second_confirmation_count;
	print "callback #2 invoked", tag, second_confirmation_count;
	if ( info?$c )
		print "  connection:", info$c$id;
	if ( info?$aid )
		print "  analyzer id:", info$aid;
	}

event zeek_init()
	{
	register_confirmation_callback(ANALYZER_HTTP, my_confirmation_callback);
	register_confirmation_callback(ANALYZER_HTTP,
					second_confirmation_callback);
	register_confirmation_callback(PacketAnalyzer::ANALYZER_TEREDO,
					second_confirmation_callback);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "confirmation:", atype;
	}

event zeek_done()
	{
	print fmt("total confirmations via callback: %d/%d",
			confirmation_count, second_confirmation_count);
	}
