zeek_add_subdir_library(
    conntuple
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
    Builder.cc
    Component.cc
    Manager.cc)

add_subdirectory(fivetuple)
