zeek_add_plugin(
    Zeek SNMP
    SOURCES SNMP.cc Plugin.cc
    BIFS types.bif events.bif
    PAC snmp.pac snmp-protocol.pac snmp-analyzer.pac
        ${PROJECT_SOURCE_DIR}/src/analyzer/protocol/asn1/asn1.pac)
