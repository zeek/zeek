module PacketAnalyzer::GTPV1;

# This needs to be loaded here so the function is available. Function BIFs normally aren't
# loaded until after the packet analysis init scripts are run, and then zeek complains it
# can't find the function.
@load base/bif/plugins/Zeek_GTPv1.events.bif
@load base/bif/plugins/Zeek_GTPv1.functions.bif

# Needed for port registration for BPF
@load base/frameworks/analyzer/main

# Needed to register Conn::RemovalHook
@load base/protocols/conn/removal-hooks

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;

	## The set of UDP ports used for GTPV1 tunnels.
	const gtpv1_ports = { 2152/udp, 2123/udp } &redef;
}


event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GTPV1, gtpv1_ports);
	}

# The analyzer keeps a BinPac interpreter per connection
# that isn't cleaned due to being stored in a global table.
hook finalize_gtpv1(c: connection)
	{
	remove_gtpv1_connection(c$id);
	}

event new_gtpv1_state(c: connection)
	{
	Conn::register_removal_hook(c, finalize_gtpv1);
	}
