
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
include_directories(AFTER  ${CMAKE_CURRENT_BINARY_DIR}/../dce-rpc)

bro_plugin_begin(Bro SMB)
bro_plugin_cc(SMB.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(smb.pac smb-protocol.pac smb-pipe.pac smb-mailslot.pac)
bro_plugin_end()
