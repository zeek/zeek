zeek_add_plugin(
    Zeek
    FileDataEvent
    SOURCES
    DataEvent.cc
    Plugin.cc
    INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}")
