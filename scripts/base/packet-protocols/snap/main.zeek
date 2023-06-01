module PacketAnalyzer::SNAP;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_SNAP, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_SNAP, 0x86DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_SNAP, 0x0806, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_SNAP, 0x8035, PacketAnalyzer::ANALYZER_ARP);
	}
