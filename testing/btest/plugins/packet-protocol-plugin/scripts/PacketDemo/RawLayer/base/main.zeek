module Packet_Raw_Layer;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ETHERNET, $identifier=0x88B5, $analyzer=PacketAnalyzer::ANALYZER_RAWLAYER),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_RAWLAYER, $identifier=0x4950, $analyzer=PacketAnalyzer::ANALYZER_IP)
};
