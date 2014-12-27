
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro AsciiWriter)
bro_plugin_cc(Ascii.cc Plugin.cc)
bro_plugin_bif(ascii.bif)
bro_plugin_end()
