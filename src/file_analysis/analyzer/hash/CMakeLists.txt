include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro FileHash)
zeek_plugin_cc(Hash.cc Plugin.cc ../../Analyzer.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_end()
