include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro RFB)
	bro_plugin_cc(RFB.cc Plugin.cc)
	bro_plugin_bif(events.bif)
	bro_plugin_pac(rfb.pac rfb-analyzer.pac rfb-protocol.pac)
bro_plugin_end()