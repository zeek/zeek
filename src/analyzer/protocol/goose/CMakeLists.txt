include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro GOOSE)
	bro_plugin_cc(GOOSE.cc Plugin.cc gooseData.cc)
	bro_plugin_bif(events.bif)
	#bro_plugin_bif(types.bif)
	bro_plugin_pac(goose.pac gooseInteger.pac asn1BitString.pac goose-protocol.pac gooseData.pac gooseFloat.pac)
bro_plugin_end()
