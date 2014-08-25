
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro KRB)
bro_plugin_cc(KRB.cc Plugin.cc)
bro_plugin_bif(types.bif)
bro_plugin_bif(events.bif)
bro_plugin_pac(krb.pac krb-protocol.pac krb-analyzer.pac)
bro_plugin_end()
