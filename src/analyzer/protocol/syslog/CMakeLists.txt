
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro Syslog)
bro_plugin_cc(Syslog.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(syslog.pac syslog-analyzer.pac syslog-protocol.pac)
bro_plugin_end()
