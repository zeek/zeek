
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek SQLiteReader)
zeek_plugin_cc(SQLite.cc Plugin.cc)
zeek_plugin_bif(sqlite.bif)
zeek_plugin_end()
