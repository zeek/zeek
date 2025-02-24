zeek_add_subdir_library(
    storage
    SOURCES
    Manager.cc
    Backend.cc
    Component.cc
    ReturnCode.cc
    BIFS
    storage.bif)

add_subdirectory(backend)
