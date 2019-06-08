include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro RDP)
	zeek_plugin_cc(RDP.cc Plugin.cc)
	zeek_plugin_bif(events.bif)
	zeek_plugin_bif(types.bif)
	zeek_plugin_pac(rdp.pac rdp-analyzer.pac rdp-protocol.pac ../asn1/asn1.pac)
zeek_plugin_end()
