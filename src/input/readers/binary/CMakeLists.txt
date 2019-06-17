
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek BinaryReader)
zeek_plugin_cc(Binary.cc Plugin.cc)
zeek_plugin_bif(binary.bif)
zeek_plugin_end()
