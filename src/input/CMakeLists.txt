zeek_add_subdir_library(
    input
    SOURCES
    Component.cc
    InputFile.cc
    Manager.cc
    ReaderBackend.cc
    ReaderFrontend.cc
    BIFS
    input.bif)

add_subdirectory(readers)
