module PacketAnalyzer::PPP_SERIAL;

export {
	## Identifier mappings
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

const DLT_PPP_SERIAL : count = 50;

redef PacketAnalyzer::ROOT::dispatch_map += {
	[DLT_PPP_SERIAL] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_PPPSERIAL)
};

redef dispatch_map += {
	[0x0281] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_MPLS),
	[0x0021] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP),
	[0x0057] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP)
};
