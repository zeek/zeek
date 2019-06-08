
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek NoneWriter)
zeek_plugin_cc(None.cc Plugin.cc)
zeek_plugin_bif(none.bif)
zeek_plugin_end()
