module PacketAnalyzer::ROOT;

export {
	## Default analyzer (if we don't know the link type, we assume raw IP)
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}
