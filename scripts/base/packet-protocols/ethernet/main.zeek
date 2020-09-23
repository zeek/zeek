module PacketAnalyzer::ETHERNET;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;

	## IEEE 802.2 SNAP analyzer
	const snap_analyzer: PacketAnalyzer::Tag &redef;
	## Novell raw IEEE 802.3 analyzer
	const novell_raw_analyzer: PacketAnalyzer::Tag &redef;
	## IEEE 802.2 LLC analyzer
	const llc_analyzer: PacketAnalyzer::Tag &redef;

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
	[0x88A8] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_VLAN),
	[0x9100] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_VLAN),
	[0x8864] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_PPPOE)
};
