
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro GTPv1)
bro_plugin_cc(GTPv1.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(gtpv1.pac gtpv1-protocol.pac gtpv1-analyzer.pac)
bro_plugin_end()
