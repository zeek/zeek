
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek Syslog)
zeek_plugin_cc(Syslog.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(syslog.pac syslog-analyzer.pac syslog-protocol.pac)
zeek_plugin_end()
