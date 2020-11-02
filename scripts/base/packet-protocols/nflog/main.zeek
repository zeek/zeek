module PacketAnalyzer::NFLOG;

const AF_INET : count = 2;
const AF_INET6 : count = 10;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NFLOG, AF_INET, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NFLOG, AF_INET6, PacketAnalyzer::ANALYZER_IP);
	}