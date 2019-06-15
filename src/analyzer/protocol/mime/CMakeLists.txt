
# This is not an actual analyzer, but used by others. We still
# maintain it here along with the other analyzers because conceptually
# it's also parsing a protocol just like them. The current structure
# is merely a left-over from when this code was written.

include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek MIME)
zeek_plugin_cc(MIME.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_end()

