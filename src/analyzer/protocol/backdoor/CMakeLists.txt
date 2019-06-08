
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Bro BackDoor)
zeek_plugin_cc(BackDoor.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_end()
