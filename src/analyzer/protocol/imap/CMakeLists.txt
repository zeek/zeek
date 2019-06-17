
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek IMAP)
zeek_plugin_cc(Plugin.cc)
zeek_plugin_cc(IMAP.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(imap.pac imap-analyzer.pac imap-protocol.pac)
zeek_plugin_end()

