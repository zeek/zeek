Zeek_add_plugin(
    Zeek SNMP
    SOURCES SNMP.cc Plugin.cc
    BIFS types.bif events.bif
    PAC snmp.pac snmp-protocol.pac snmp-analyzer.pac
        ${PROJECT_SOURCE_DIR}/src/analyzer/protocol/asn1/asn1.pac)

If (USE_SPICY_ANALYZERS)
    spicy_add_analyzer(NAME SNMP SOURCES snmp.spicy snmp.evt asn1.spicy MODULES SNMP ASN1)
Endif ()
