
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro Pcap)
bro_plugin_cc(Source.cc Dumper.cc Plugin.cc)
bif_target(functions.bif)
bif_target(const.bif)
bro_plugin_end()
