
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro BinaryReader)
bro_plugin_cc(Binary.cc Plugin.cc)
bro_plugin_bif(binary.bif)
bro_plugin_end()
