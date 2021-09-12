
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek Statistics)
zeek_plugin_cc(Plugin.cc)
bif_target(statistics.bif)
zeek_plugin_end()
