zeek_add_subdir_library(
    analyzer
    INTERNAL_DEPENDENCIES
    ${BIF_BUILD_TARGET}
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
    Analyzer.cc
    Component.cc
    Manager.cc)

# Treat BIFs as builtin (alternative mode).
bif_target(analyzer.bif)

add_subdirectory(protocol)
