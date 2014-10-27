
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro RawReader)
bro_plugin_cc(Raw.cc Plugin.cc)
bro_plugin_bif(raw.bif)
bro_plugin_end()
