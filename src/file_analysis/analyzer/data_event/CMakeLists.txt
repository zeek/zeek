include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek FileDataEvent)
zeek_plugin_cc(DataEvent.cc Plugin.cc ../../Analyzer.cc)
zeek_plugin_end()
