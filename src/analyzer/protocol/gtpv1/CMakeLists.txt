
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek GTPv1)
zeek_plugin_cc(GTPv1.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(gtpv1.pac gtpv1-protocol.pac gtpv1-analyzer.pac)
zeek_plugin_end()
