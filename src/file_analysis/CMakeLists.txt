zeek_add_subdir_library(
    file_analysis
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
        Manager.cc
        File.cc
        FileTimer.cc
        FileReassembler.cc
        Analyzer.cc
        AnalyzerSet.cc
        Component.cc
)

# Treat BIFs as builtin (alternative mode).
bif_target(file_analysis.bif)

add_subdirectory(analyzer)
