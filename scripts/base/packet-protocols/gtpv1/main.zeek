module PacketAnalyzer::GTPV1;

# This needs to be loaded here so the function is available. Function BIFs normally aren't
# loaded until after the packet analysis init scripts are run, and then zeek complains it
# can't find the function.
@load base/bif/plugins/Zeek_GTPv1.functions.bif

# Needed for port registration for BPF
@load base/frameworks/analyzer/main

export {
        ## Default analyzer
        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

const gtpv1_ports = { 2152/udp, 2123/udp };
redef likely_server_ports += { gtpv1_ports };

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GTPV1, gtpv1_ports);
	}

event connection_state_remove(c: connection)
	{
	remove_gtpv1_connection(c$id);
	}
