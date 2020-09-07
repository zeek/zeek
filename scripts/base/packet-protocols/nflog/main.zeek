module PacketAnalyzer::NFLOG;

const DLT_NFLOG : count = 239;
const AF_INET : count = 2;
const AF_INET6 : count = 10;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ROOT, $identifier=DLT_NFLOG, $analyzer=PacketAnalyzer::ANALYZER_NFLOG),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_NFLOG, $identifier=AF_INET, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_NFLOG, $identifier=AF_INET6, $analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
