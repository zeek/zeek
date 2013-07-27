
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro Login)
bro_plugin_cc(Login.cc RSH.cc Telnet.cc Rlogin.cc NVT.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_bif(functions.bif)
bro_plugin_end()
