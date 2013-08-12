include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro FileDataEvent)
bro_plugin_cc(DataEvent.cc Plugin.cc ../../Analyzer.cc)
bro_plugin_end()
