module PacketAnalyzer::TEREDO;

# This needs to be loaded here so the functions are available. Function BIFs normally aren't
# loaded until after the packet analysis init scripts are run, and then zeek complains it
# can't find the function.
@load base/bif/plugins/Zeek_Teredo.events.bif.zeek
@load base/bif/plugins/Zeek_Teredo.functions.bif

# Needed for port registration for BPF
@load base/frameworks/analyzer/main

# Needed to register Conn::RemovalHook
@load base/protocols/conn/removal-hooks

export {
        ## Default analyzer
        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

const teredo_ports = { 3544/udp } &redef;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_protocol_detection(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_TEREDO);
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_TEREDO, teredo_ports);
	}

# The analyzer keeps state about each Teredo connection in the
# orig_resp_map. Register cleanup.
hook finalize_teredo(c: connection)
	{
	remove_teredo_connection(c$id);
	}

event new_teredo_state(c: connection)
	{
	Conn::register_removal_hook(c, finalize_teredo);
	}
