zeek_add_plugin(
    Zeek
    SQLiteWriter
    SOURCES
    SQLite.cc
    Plugin.cc
    BIFS
    sqlite.bif)
