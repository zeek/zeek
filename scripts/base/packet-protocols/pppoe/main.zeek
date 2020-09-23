module PacketAnalyzer::PPPOE;

export {
	## Identifier mappings
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

redef dispatch_map += {
	[0x0021] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP),
	[0x0057] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP)
};
