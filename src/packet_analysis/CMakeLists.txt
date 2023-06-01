zeek_add_subdir_library(
    packet_analysis
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
    Analyzer.cc
    Dispatcher.cc
    Manager.cc
    Component.cc)

add_subdirectory(protocol)
