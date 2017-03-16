
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro GSSAPI)
bro_plugin_cc(GSSAPI.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(
    gssapi.pac 
    gssapi-protocol.pac
    gssapi-analyzer.pac
    ../asn1/asn1.pac
    )
bro_plugin_end()

