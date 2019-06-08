
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro RADIUS)
zeek_plugin_cc(RADIUS.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(radius.pac radius-analyzer.pac radius-protocol.pac)
zeek_plugin_end()
