
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro NTLM)
bro_plugin_cc(NTLM.cc Plugin.cc)
bro_plugin_bif(types.bif events.bif)
bro_plugin_pac(
    ntlm.pac
    ntlm-protocol.pac
    ntlm-analyzer.pac
    )
bro_plugin_end()

