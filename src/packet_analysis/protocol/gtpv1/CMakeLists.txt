zeek_add_plugin(
    Zeek GTPv1
    SOURCES GTPv1.cc Plugin.cc
    BIFS events.bif functions.bif
    PAC gtpv1.pac gtpv1-protocol.pac gtpv1-analyzer.pac)
