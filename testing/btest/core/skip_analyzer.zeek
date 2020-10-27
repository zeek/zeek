# @TEST-EXEC: zeek -b -C -r $TRACES/tunnels/gre-sample.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: test ! -e tunnel.log

# Test the skip analyzer by skipping everything outside the GRE tunnel.

@load base/protocols/conn
@load base/frameworks/tunnels

redef PacketAnalyzer::SKIP::skip_bytes: count = 38;

event zeek_init()
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, 1, PacketAnalyzer::ANALYZER_SKIP);
	}
