include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro RDP)
	bro_plugin_cc(RDP.cc Plugin.cc)
	bro_plugin_bif(events.bif)
	bro_plugin_bif(types.bif)
	bro_plugin_pac(rdp.pac rdp-analyzer.pac rdp-protocol.pac ../asn1/asn1.pac)
bro_plugin_end()
