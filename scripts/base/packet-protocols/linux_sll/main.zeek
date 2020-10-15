module PacketAnalyzer::LINUXSLL;

export {
	## Identifier mappings based on EtherType
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

redef dispatch_map += {
	[0x0800] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP),
	[0x86DD] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP),
	[0x0806] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_ARP),
	# RARP
	[0x8035] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_ARP)
};
