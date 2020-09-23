module PacketAnalyzer::IP;

export {
	## Identifier mappings based on IP version (4 or 6)
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

redef dispatch_map += {
	[4] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPTUNNEL),    # IPv4 tunnel
	[41] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPTUNNEL),   # IPv6 tunnel
	[47] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_GRE)
};
