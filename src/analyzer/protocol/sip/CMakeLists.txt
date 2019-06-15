
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek SIP)
zeek_plugin_cc(Plugin.cc)
zeek_plugin_cc(SIP.cc)
zeek_plugin_cc(SIP_TCP.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(sip.pac sip-analyzer.pac sip-protocol.pac)
zeek_plugin_pac(sip_TCP.pac sip-protocol.pac sip-analyzer.pac)
zeek_plugin_end()

