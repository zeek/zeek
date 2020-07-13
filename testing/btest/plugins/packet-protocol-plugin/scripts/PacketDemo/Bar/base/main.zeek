module Packet_BAR;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ETHERNET, $identifier=1501, $analyzer=PacketAnalyzer::ANALYZER_BAR),
};
