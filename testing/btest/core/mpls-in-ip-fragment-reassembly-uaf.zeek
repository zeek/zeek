# @TEST-DOC: Same issue as with skip-fragment-reassembly-uaf, but using MPLS-in-IP which isn't default registered but does actually exist via RFC 4023 (proto=137)
#
# @TEST-EXEC: zeek -b -C -r $TRACES/mpls/mpls-in-ip-fragment-reassembly-uaf.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/frameworks/tunnels

redef PacketAnalyzer::SKIP::skip_bytes = 14;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 137, PacketAnalyzer::ANALYZER_MPLS);
	}

event raw_packet(p: raw_pkt_hdr)
	{
	print p$ip;
	}
