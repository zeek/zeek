
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro NoneWriter)
bro_plugin_cc(None.cc Plugin.cc)
bro_plugin_bif(none.bif)
bro_plugin_end()
