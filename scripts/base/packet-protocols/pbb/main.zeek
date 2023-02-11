module PacketAnalyzer::PBB;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x86DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x0806, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x8035, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x8100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x8100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x88A8, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x9100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PBB, 0x8864, PacketAnalyzer::ANALYZER_PPPOE);
	}
