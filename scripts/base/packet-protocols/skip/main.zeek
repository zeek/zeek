module PacketAnalyzer::SkipAnalyzer;

export {
	## Bytes to skip.
	const skip_bytes: count = 0 &redef;
}

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_SKIP, $analyzer=PacketAnalyzer::ANALYZER_DEFAULTANALYZER)
};
