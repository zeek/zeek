module PacketAnalyzer::LINUXSLL2;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_LINUXSLL2, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_LINUXSLL2, 0x86DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_LINUXSLL2, 0x0806, PacketAnalyzer::ANALYZER_ARP);

	# RARP
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_LINUXSLL2, 0x8035, PacketAnalyzer::ANALYZER_ARP);
	}
