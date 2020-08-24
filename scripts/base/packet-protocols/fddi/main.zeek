module LL_FDDI;

const DLT_FDDI : count = 10;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($identifier=DLT_FDDI, $analyzer=PacketAnalyzer::ANALYZER_FDDI),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_FDDI, $analyzer=PacketAnalyzer::ANALYZER_DEFAULTANALYZER)
};
