
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek GSSAPI)
zeek_plugin_cc(GSSAPI.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(
    gssapi.pac 
    gssapi-protocol.pac
    gssapi-analyzer.pac
    ../asn1/asn1.pac
    )
zeek_plugin_end()

