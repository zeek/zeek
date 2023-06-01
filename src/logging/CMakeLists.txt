zeek_add_subdir_library(
    logging
    SOURCES
    Component.cc
    Manager.cc
    WriterBackend.cc
    WriterFrontend.cc
    BIFS
    logging.bif)

add_subdirectory(writers)
