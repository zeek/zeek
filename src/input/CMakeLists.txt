zeek_add_subdir_library(
    input
    SOURCES
        Component.cc
        Manager.cc
        ReaderBackend.cc
        ReaderFrontend.cc
)

# Treat BIFs as builtin (alternative mode).
bif_target(input.bif)

add_subdirectory(readers)
