include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro FileEntropy)
bro_plugin_cc(Entropy.cc Plugin.cc ../../Analyzer.cc)
bro_plugin_bif(events.bif)
bro_plugin_end()
