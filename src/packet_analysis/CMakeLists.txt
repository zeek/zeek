
include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(protocol)

set(packet_analysis_SRCS
    Analyzer.cc
    Dispatcher.cc
    Manager.cc
    Component.cc
    Tag.cc
    )

bro_add_subdir_library(packet_analysis ${packet_analysis_SRCS})
add_dependencies(bro_packet_analysis generate_outputs)
