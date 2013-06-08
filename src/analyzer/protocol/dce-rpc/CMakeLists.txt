
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro DCE_RPC)
bro_plugin_cc(DCE_RPC.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(dce_rpc.pac dce_rpc-protocol.pac dce_rpc-analyzer.pac)
bro_plugin_pac(dce_rpc_simple.pac dce_rpc-protocol.pac epmapper.pac)
bro_plugin_end()

