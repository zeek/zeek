include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(protocol)

set(llanalyzer_SRCS
    Analyzer.cc
    Dispatcher.cc
    Manager.cc
    Component.cc
    Tag.cc
    Config.cc
)

bro_add_subdir_library(llanalyzer ${llanalyzer_SRCS})
add_dependencies(bro_llanalyzer generate_outputs)
