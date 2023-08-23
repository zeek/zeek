module PacketAnalyzer::PPP;

const DLT_PPP: count = 9;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_PPP, PacketAnalyzer::ANALYZER_PPP);

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPP, 0x0281, PacketAnalyzer::ANALYZER_MPLS);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPP, 0x0021, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPP, 0x0057, PacketAnalyzer::ANALYZER_IP);
	}
