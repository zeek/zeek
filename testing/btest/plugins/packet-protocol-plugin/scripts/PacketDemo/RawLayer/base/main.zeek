module PacketAnalyzer::RAW_LAYER;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88B5, PacketAnalyzer::ANALYZER_RAW_LAYER);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_RAW_LAYER, 0x4950, PacketAnalyzer::ANALYZER_IP);
	}
