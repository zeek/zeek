
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SOCKS)
bro_plugin_cc(SOCKS.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(socks.pac socks-protocol.pac socks-analyzer.pac)
bro_plugin_end()
