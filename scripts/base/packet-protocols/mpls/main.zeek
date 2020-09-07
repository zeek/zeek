module PacketAnalyzer::MPLS;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}
