module PacketAnalyzer::IEEE802_11_RADIO;

const DLT_IEEE802_11_RADIO : count = 127;
const DLT_IEEE802_11 : count = 105;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ROOT, $identifier=DLT_IEEE802_11_RADIO, $analyzer=PacketAnalyzer::ANALYZER_IEEE802_11_RADIO),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IEEE802_11_RADIO, $identifier=DLT_IEEE802_11, $analyzer=PacketAnalyzer::ANALYZER_IEEE802_11)
};
