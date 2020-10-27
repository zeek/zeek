module PacketAnalyzer::VLAN;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x8847, PacketAnalyzer::ANALYZER_MPLS);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x86DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x0806, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x8035, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x8100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x8864, PacketAnalyzer::ANALYZER_PPPOE);
	}
