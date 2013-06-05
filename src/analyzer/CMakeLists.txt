
include(BroSubdir)

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

bro_add_subdir_library(analyzer ${analyzer_SRCS} ${BIF_OUTPUT_CC})
add_dependencies(bro_analyzer generate_outputs)

