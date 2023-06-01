zeek_add_plugin(
    Zeek
    SQLiteReader
    SOURCES
    SQLite.cc
    Plugin.cc
    BIFS
    sqlite.bif)
