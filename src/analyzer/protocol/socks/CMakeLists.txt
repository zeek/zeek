
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro SOCKS)
zeek_plugin_cc(SOCKS.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(socks.pac socks-protocol.pac socks-analyzer.pac)
zeek_plugin_end()
