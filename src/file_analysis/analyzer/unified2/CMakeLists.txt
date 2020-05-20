
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek Unified2)
zeek_plugin_cc(Unified2.cc Plugin.cc)
zeek_plugin_bif(events.bif types.bif)
zeek_plugin_pac(unified2.pac unified2-file.pac unified2-analyzer.pac)
zeek_plugin_end()
