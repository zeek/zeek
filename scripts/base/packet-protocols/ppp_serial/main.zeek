module PacketAnalyzer::PPP_SERIAL;

const DLT_PPP_SERIAL : count = 50;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ROOT, $identifier=DLT_PPP_SERIAL, $analyzer=PacketAnalyzer::ANALYZER_PPPSERIAL),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_PPPSERIAL, $identifier=0x0281, $analyzer=PacketAnalyzer::ANALYZER_MPLS),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_PPPSERIAL, $identifier=0x0021, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_PPPSERIAL, $identifier=0x0057, $analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
