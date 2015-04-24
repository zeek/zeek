
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro SQLiteReader)
bro_plugin_cc(SQLite.cc Plugin.cc)
bro_plugin_bif(sqlite.bif)
bro_plugin_end()
