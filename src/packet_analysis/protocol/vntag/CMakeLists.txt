
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(PacketAnalyzer VNTag)
zeek_plugin_cc(VNTag.cc Plugin.cc)
zeek_plugin_end()
