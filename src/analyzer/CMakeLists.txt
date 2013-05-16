
include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(protocol)

set(analyzer_SRCS
    Analyzer.cc
    Manager.cc
    Component.cc
    Tag.cc
)

bif_target(analyzer.bif)
add_library(bro_analyzer OBJECT ${analyzer_SRCS} ${BIF_OUTPUT_CC})
add_dependencies(bro_analyzer generate_outputs)
