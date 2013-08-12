
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro DNP3)
bro_plugin_cc(DNP3.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(dnp3.pac dnp3-analyzer.pac dnp3-protocol.pac dnp3-objects.pac)
bro_plugin_end()
