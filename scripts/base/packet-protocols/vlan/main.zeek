module PacketAnalyzer::VLAN;

export {
	## Identifier mappings based on EtherType
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

redef dispatch_map += {
   [0x8847] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_MPLS),
   [0x0800] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPV4),
   [0x86DD] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPV6),
   [0x0806] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_ARP),
   [0x8035] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_ARP),
   [0x8100] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_VLAN),
   [0x8864] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_PPPOE)
};
