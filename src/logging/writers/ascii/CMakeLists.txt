
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek AsciiWriter)
zeek_plugin_cc(Ascii.cc Plugin.cc)
zeek_plugin_bif(ascii.bif)
zeek_plugin_end()
