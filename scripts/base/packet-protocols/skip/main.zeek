module PacketAnalyzer::SKIP;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;

	## Bytes to skip.
	const skip_bytes: count = 0 &redef;
}
