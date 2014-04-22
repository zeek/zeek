
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro Unified2)
bro_plugin_cc(Unified2.cc Plugin.cc ../../Analyzer.cc)
bro_plugin_bif(events.bif types.bif)
bro_plugin_pac(unified2.pac unified2-file.pac unified2-analyzer.pac)
bro_plugin_end()
