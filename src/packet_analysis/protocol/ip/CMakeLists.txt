zeek_add_plugin(
    PacketAnalyzer
    IP
    SOURCES
    IP.cc
    IPBasedAnalyzer.cc
    SessionAdapter.cc
    Plugin.cc)

add_subdirectory(conn_key)
