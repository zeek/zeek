module PacketAnalyzer::VNTAG;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VNTAG, 0x8100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VNTAG, 0x88A8, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VNTAG, 0x9100, PacketAnalyzer::ANALYZER_VLAN);
	}
