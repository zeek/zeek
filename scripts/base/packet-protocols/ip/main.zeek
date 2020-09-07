module PacketAnalyzer::IP;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IP, $identifier=4, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IP, $identifier=6, $analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
