module PacketAnalyzer::RAW_LAYER;

export {
	## Identifier mapping
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

redef PacketAnalyzer::ETHERNET::dispatch_map += {
	[0x88B5] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_RAW_LAYER)
};

redef dispatch_map += {
	[0x4950] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP)
};
