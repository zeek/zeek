
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro ZIP_File)
bro_plugin_cc(ZIP_File.cc Plugin.cc ../../Analyzer.cc)
bro_plugin_bif(events.bif types.bif)
bro_plugin_pac(zip.pac zip-file.pac zip-analyzer.pac)
bro_plugin_end()
