
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro NTLM)
zeek_plugin_cc(NTLM.cc Plugin.cc)
zeek_plugin_bif(types.bif events.bif)
zeek_plugin_pac(
    ntlm.pac
    ntlm-protocol.pac
    ntlm-analyzer.pac
    )
zeek_plugin_end()

