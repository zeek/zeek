
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(PacketAnalyzer IEEE802_11)
zeek_plugin_cc(IEEE802_11.cc Plugin.cc)
zeek_plugin_end()
