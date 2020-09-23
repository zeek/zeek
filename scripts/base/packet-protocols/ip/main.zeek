module PacketAnalyzer::IP;

export {
	## Identifier mappings based on IP version (4 or 6)
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

redef dispatch_map += {
	[4] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPV4),
	[6] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
