module PacketAnalyzer::PPP_SERIAL;

const DLT_PPP_SERIAL : count = 50;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_PPP_SERIAL, PacketAnalyzer::ANALYZER_PPPSERIAL);

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPPSERIAL, 0x0281, PacketAnalyzer::ANALYZER_MPLS);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPPSERIAL, 0x0021, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_PPPSERIAL, 0x0057, PacketAnalyzer::ANALYZER_IP);
	}