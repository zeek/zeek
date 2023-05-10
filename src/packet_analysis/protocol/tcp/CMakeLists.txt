zeek_add_plugin(
    PacketAnalyzer
    TCP_PKT
    SOURCES
    TCP.cc
    TCPSessionAdapter.cc
    Plugin.cc
    Stats.cc)
