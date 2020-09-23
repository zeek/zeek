module PacketAnalyzer::NFLOG;

export {
	## Identifier mappings
	const dispatch_map: PacketAnalyzer::DispatchMap = {} &redef;
}

const AF_INET : count = 2;
const AF_INET6 : count = 10;

redef dispatch_map += {
	[AF_INET] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPV4),
	[AF_INET6] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
