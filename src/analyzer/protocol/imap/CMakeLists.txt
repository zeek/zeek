
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro IMAP)
bro_plugin_cc(Plugin.cc)
bro_plugin_cc(IMAP.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(imap.pac imap-analyzer.pac imap-protocol.pac)
bro_plugin_end()

