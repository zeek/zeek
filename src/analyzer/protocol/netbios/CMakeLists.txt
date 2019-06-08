
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
include_directories(AFTER ${CMAKE_CURRENT_BINARY_DIR}/../dce-rpc)
include_directories(AFTER ${CMAKE_CURRENT_BINARY_DIR}/../smb)

zeek_plugin_begin(Bro NetBIOS)
zeek_plugin_cc(NetbiosSSN.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_bif(functions.bif)
zeek_plugin_end()

