
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek ConfigReader)
zeek_plugin_cc(Config.cc Plugin.cc)
zeek_plugin_bif(config.bif)
zeek_plugin_end()
