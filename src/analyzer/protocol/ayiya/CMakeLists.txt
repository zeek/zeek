
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro AYIYA)
bro_plugin_cc(AYIYA.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(ayiya.pac ayiya-protocol.pac ayiya-analyzer.pac)
bro_plugin_end()
