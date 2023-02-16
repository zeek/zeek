module PacketAnalyzer::PBB;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);
	}
