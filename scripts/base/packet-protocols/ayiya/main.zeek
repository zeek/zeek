module PacketAnalyzer::AYIYA;

# Needed for port registration for BPF
@load base/frameworks/analyzer/main

const IPPROTO_IPV4 : count = 4;
const IPPROTO_IPV6 : count = 41;

const ayiya_ports = { 5072/udp };
redef likely_server_ports += { ayiya_ports };

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_protocol_detection(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_AYIYA);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_AYIYA, IPPROTO_IPV4, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_AYIYA, IPPROTO_IPV6, PacketAnalyzer::ANALYZER_IP);

	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_AYIYA, ayiya_ports);
	}
