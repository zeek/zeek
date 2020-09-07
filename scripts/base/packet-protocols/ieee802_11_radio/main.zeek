module PacketAnalyzer::IEEE802_11_RADIO;

export {
	## Identifier mappings
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

const DLT_IEEE802_11 : count = 105;

redef dispatch_map += {
	[DLT_IEEE802_11] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IEEE802_11)
};
