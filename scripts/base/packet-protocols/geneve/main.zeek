module PacketAnalyzer::Geneve;

export {
	## The set of UDP ports used for Geneve traffic.  Traffic using this
	## UDP destination port will attempt to be decapsulated.  Note that if
	## if you customize this, you may still want to manually ensure that
	## :zeek:see:`likely_server_ports` also gets populated accordingly.
	const geneve_ports: set[port] = { 6081/udp } &redef;
}

redef likely_server_ports += { geneve_ports };

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GENEVE, geneve_ports);

	# This is defined by IANA as being "Trans Ether Bridging" but the Geneve RFC
	# says to use it for Ethernet. See
	# https://datatracker.ietf.org/doc/html/draft-gross-geneve-00#section-3.4
	# for details.
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);

	# Some additional mappings for protocols that we already handle natively.
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x08DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x0806, PacketAnalyzer::ANALYZER_ARP);
	}
