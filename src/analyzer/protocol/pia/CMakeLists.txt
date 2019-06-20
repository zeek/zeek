
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek PIA)
zeek_plugin_cc(PIA.cc Plugin.cc)
zeek_plugin_end()
