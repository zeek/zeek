
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek Pcap)
zeek_plugin_cc(Source.cc Dumper.cc Plugin.cc)
bif_target(pcap.bif)
zeek_plugin_end()
