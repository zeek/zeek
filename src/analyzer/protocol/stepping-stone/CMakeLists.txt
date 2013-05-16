
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SteppingStone)
bro_plugin_cc(SteppingStone.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_end()
