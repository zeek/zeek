
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro TCP)
bro_plugin_cc(TCP.cc TCP_Endpoint.cc TCP_Reassembler.cc ContentLine.cc Stats.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_bif(functions.bif)
bro_plugin_end()
