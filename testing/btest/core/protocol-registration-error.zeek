# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stderr

event try_register()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, 12345, PacketAnalyzer::ANALYZER_ETHERNET);
	}

event zeek_init()
	{
	schedule 1sec { try_register() };
	}