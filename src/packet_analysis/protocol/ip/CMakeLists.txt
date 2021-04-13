
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(PacketAnalyzer IP)
zeek_plugin_cc(IP.cc IPBasedAnalyzer.cc Plugin.cc)
zeek_plugin_end()
