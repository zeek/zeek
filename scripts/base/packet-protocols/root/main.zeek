module PacketAnalyzer::ROOT;

export {
	## Default analyzer (if we don't know the link type, we assume raw IP)
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;

	## Identifier mappings based on link type
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

const DLT_EN10MB : count = 1;
const DLT_FDDI : count = 10;
const DLT_IEEE802_11 : count = 105;
const DLT_IEEE802_11_RADIO : count = 127;
const DLT_LINUX_SLL : count = 113;
const DLT_NFLOG : count = 239;

redef dispatch_map += {
	[DLT_EN10MB] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_ETHERNET),
	[DLT_FDDI] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_FDDI),
	[DLT_IEEE802_11] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IEEE802_11),
	[DLT_IEEE802_11_RADIO] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IEEE802_11_RADIO),
	[DLT_LINUX_SLL] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_LINUXSLL),
	[DLT_NFLOG] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_NFLOG)

};
