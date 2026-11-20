# @TEST-DOC: The skip analyzer by default forwards into IP. An outer fragmented IP with a proto field that uses skip resulted in a use-after-free when passed through the skip analyzer as there's no new Packet instance created and the IP analyzer overwrites packet->ip_hdr freeing the reassembled packet!
#
# @TEST-EXEC: zeek -b -C -r $TRACES/ipv4/skip-fragment-reassembly-uaf.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/frameworks/tunnels

redef PacketAnalyzer::SKIP::skip_bytes = 14;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 253, PacketAnalyzer::ANALYZER_SKIP);
	}

event raw_packet(p: raw_pkt_hdr)
	{
	print p$ip;
	}
