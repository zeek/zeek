module LL_PPPOE;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_PPPOE, $identifier=0x0021, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_PPPOE, $identifier=0x0057, $analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
