zeek_add_subdir_library(
    storage
    SOURCES
    Manager.cc
    Backend.cc
    Component.cc
    ReturnCodes.cc
    BIFS
    storage.bif)

add_subdirectory(backends)
