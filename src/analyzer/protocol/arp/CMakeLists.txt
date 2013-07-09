
# This is not an actual analyzer, but used by the core. We still
# maintain it here along with the other analyzers because conceptually
# it's also parsing a protocol just like them. The current structure
# is merely a left-over from when this code was written.

include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro ARP)
bro_plugin_cc(ARP.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_end()

