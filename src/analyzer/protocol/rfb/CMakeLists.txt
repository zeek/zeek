include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek RFB)
	zeek_plugin_cc(RFB.cc Plugin.cc)
	zeek_plugin_bif(events.bif)
	zeek_plugin_pac(rfb.pac rfb-analyzer.pac rfb-protocol.pac)
zeek_plugin_end()
