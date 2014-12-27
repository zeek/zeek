
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SSL)
bro_plugin_cc(SSL.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(ssl.pac ssl-analyzer.pac ssl-protocol.pac ssl-defs.pac)
bro_plugin_end()
