
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek NCP)
zeek_plugin_cc(NCP.cc Plugin.cc)
zeek_plugin_bif(events.bif consts.bif)
zeek_plugin_pac(ncp.pac)
zeek_plugin_end()
