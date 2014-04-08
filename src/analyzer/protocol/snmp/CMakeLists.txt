include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SNMP)
bro_plugin_cc(SNMP.cc Plugin.cc)
bro_plugin_bif(types.bif)
bro_plugin_bif(events.bif)
bro_plugin_pac(snmp.pac snmp-protocol.pac snmp-analyzer.pac)
bro_plugin_end()
