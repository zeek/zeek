
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek DCE_RPC)
zeek_plugin_cc(DCE_RPC.cc Plugin.cc)
zeek_plugin_bif(consts.bif types.bif events.bif)
zeek_plugin_pac(
    dce_rpc.pac
    dce_rpc-protocol.pac
    dce_rpc-analyzer.pac
    dce_rpc-auth.pac
    endpoint-atsvc.pac
    endpoint-epmapper.pac
    )
zeek_plugin_end()

