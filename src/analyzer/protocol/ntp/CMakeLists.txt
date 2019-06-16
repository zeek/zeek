
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek NTP)
zeek_plugin_cc(NTP.cc Plugin.cc)
zeek_plugin_bif(types.bif events.bif)
zeek_plugin_pac(ntp.pac ntp-analyzer.pac ntp-mode7.pac ntp-protocol.pac)
zeek_plugin_end()
