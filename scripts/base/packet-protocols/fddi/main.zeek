module PacketAnalyzer::FDDI;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

const DLT_FDDI : count = 10;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ROOT, $identifier=DLT_FDDI, $analyzer=PacketAnalyzer::ANALYZER_FDDI),
};
