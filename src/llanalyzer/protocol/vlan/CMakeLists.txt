
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(LLAnalyzer VLAN)
zeek_plugin_cc(VLAN.cc Plugin.cc)
zeek_plugin_end()
