module PacketAnalyzer::LINUX_SLL;

const DLT_LINUX_SLL : count = 113;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($identifier=DLT_LINUX_SLL, $analyzer=PacketAnalyzer::ANALYZER_LINUXSLL),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_LINUXSLL, $identifier=0x0800, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_LINUXSLL, $identifier=0x86DD, $analyzer=PacketAnalyzer::ANALYZER_IPV6),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_LINUXSLL, $identifier=0x0806, $analyzer=PacketAnalyzer::ANALYZER_ARP),
	# RARP
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_LINUXSLL, $identifier=0x8035, $analyzer=PacketAnalyzer::ANALYZER_ARP)
};
