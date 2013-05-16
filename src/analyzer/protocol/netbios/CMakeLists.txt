
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
include_directories(AFTER ${CMAKE_CURRENT_BINARY_DIR}/../dce-rpc)
include_directories(AFTER ${CMAKE_CURRENT_BINARY_DIR}/../smb)

bro_plugin_begin(Bro NetBIOS)
bro_plugin_cc(NetbiosSSN.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_bif(functions.bif)
bro_plugin_end()

