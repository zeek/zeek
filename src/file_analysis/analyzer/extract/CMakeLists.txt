include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro FileExtract)
zeek_plugin_cc(Extract.cc Plugin.cc ../../Analyzer.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_bif(functions.bif)
zeek_plugin_end()
