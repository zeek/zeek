
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek HTTP)
zeek_plugin_cc(HTTP.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_bif(functions.bif)
zeek_plugin_end()
