module PacketAnalyzer::PPPOE;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPPOE, 0x0021, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPPOE, 0x0057, PacketAnalyzer::ANALYZER_IP);
	}