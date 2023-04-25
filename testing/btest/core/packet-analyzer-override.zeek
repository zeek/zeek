# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff reporter.log

@load base/frameworks/reporter

redef PacketAnalyzer::SKIP::skip_bytes: count = 0;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x0800, PacketAnalyzer::ANALYZER_SKIP);
	}
