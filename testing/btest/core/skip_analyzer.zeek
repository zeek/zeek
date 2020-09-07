# @TEST-EXEC: zeek -b -C -r $TRACES/tunnels/gre-sample.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: test ! -e tunnel.log

# Test the skip analyzer by skipping everything outside the GRE tunnel.

@load base/protocols/conn
@load base/frameworks/tunnels

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_ROOT, $identifier=1, $analyzer=PacketAnalyzer::ANALYZER_SKIP)
};

redef PacketAnalyzer::SKIP::skip_bytes: count = 38;
