include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(analyzer)

set(file_analysis_SRCS
    Manager.cc
    File.cc
    FileTimer.cc
    Analyzer.cc
    AnalyzerSet.cc
    Component.cc
    Tag.cc
)

bif_target(file_analysis.bif)

bro_add_subdir_library(file_analysis ${file_analysis_SRCS} ${BIF_OUTPUT_CC})
add_dependencies(bro_file_analysis generate_outputs)
