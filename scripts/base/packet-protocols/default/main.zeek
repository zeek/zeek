module PacketAnalyzer::Default;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($analyzer=PacketAnalyzer::ANALYZER_DEFAULTANALYZER),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_DEFAULTANALYZER, $identifier=4, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_DEFAULTANALYZER, $identifier=6, $analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
