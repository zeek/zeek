include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(protocol)
add_subdirectory(dispatchers)

set(llanalyzer_SRCS
    Analyzer.cc
    ProtocolAnalyzerSet.cc
    Manager.cc
    Component.cc
    Tag.cc
    Config.cc
)

bro_add_subdir_library(llanalyzer ${llanalyzer_SRCS})
add_dependencies(bro_llanalyzer generate_outputs)
