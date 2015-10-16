
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SIP)
bro_plugin_cc(Plugin.cc)
bro_plugin_cc(SIP.cc)
bro_plugin_cc(SIP_TCP.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(sip.pac sip-analyzer.pac sip-protocol.pac)
bro_plugin_pac(sip_TCP.pac sip-protocol.pac sip-analyzer.pac)
bro_plugin_end()

