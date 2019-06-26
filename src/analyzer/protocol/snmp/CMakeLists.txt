include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek SNMP)
zeek_plugin_cc(SNMP.cc Plugin.cc)
zeek_plugin_bif(types.bif)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(snmp.pac snmp-protocol.pac snmp-analyzer.pac ../asn1/asn1.pac)
zeek_plugin_end()
