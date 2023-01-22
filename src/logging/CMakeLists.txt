zeek_add_subdir_library(
    logging
    SOURCES
        Component.cc
        Manager.cc
        WriterBackend.cc
        WriterFrontend.cc
)

# Treat BIFs as builtin (alternative mode).
bif_target(logging.bif)

add_subdirectory(writers)
