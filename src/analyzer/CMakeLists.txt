
include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(protocols)

set(analyzer_SRCS
    Analyzer.cc
    Manager.cc
    Component.cc
    Tag.cc
)

bif_target_for_subdir(analyzer.bif)

bro_plugin_dependencies(DCE_RPC generate_analyzer.bif)

add_library(bro_analyzer OBJECT ${analyzer_SRCS} ${BIF_OUTPUT_CC} ${BIF_OUTPUT_H})

add_dependencies(bro_analyzer generate_events.bif)
