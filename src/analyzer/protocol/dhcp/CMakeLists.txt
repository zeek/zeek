
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek DHCP)
zeek_plugin_cc(DHCP.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_bif(types.bif)
zeek_plugin_pac(dhcp.pac dhcp-protocol.pac dhcp-analyzer.pac dhcp-options.pac)
zeek_plugin_end()
