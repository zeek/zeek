zeek_add_subdir_library(
    cluster
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
    Backend.cc
    BifSupport.cc
    Component.cc
    Manager.cc
    Telemetry.cc
    BIFS
    cluster.bif)

add_subdirectory(backend)
add_subdirectory(serializer)
add_subdirectory(websocket)
