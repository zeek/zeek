
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek OpenVPN)
zeek_plugin_cc(OpenVPN.cc Plugin.cc)
zeek_plugin_pac(openvpn.pac openvpn-protocol.pac)
zeek_plugin_end()
