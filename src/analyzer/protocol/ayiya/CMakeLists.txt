
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro AYIYA)
zeek_plugin_cc(AYIYA.cc Plugin.cc)
zeek_plugin_pac(ayiya.pac ayiya-protocol.pac ayiya-analyzer.pac)
zeek_plugin_end()
