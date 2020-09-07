module PacketAnalyzer::IEEE802_11;

const DLT_IEEE802_11 : count = 105;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ROOT, $identifier=DLT_IEEE802_11, $analyzer=PacketAnalyzer::ANALYZER_IEEE802_11),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IEEE802_11, $identifier=0x0800, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IEEE802_11, $identifier=0x86DD, $analyzer=PacketAnalyzer::ANALYZER_IPV6),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IEEE802_11, $identifier=0x0806, $analyzer=PacketAnalyzer::ANALYZER_ARP),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_IEEE802_11, $identifier=0x8035, $analyzer=PacketAnalyzer::ANALYZER_ARP)
};
