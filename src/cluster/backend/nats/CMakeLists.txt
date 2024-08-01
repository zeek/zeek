list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

message(STATUS "XXXXX ${CMAKE_MODULE_PATH}")

find_package(LibNATS REQUIRED)

zeek_add_plugin(
    Zeek
    Cluster_Backend_NATS
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBNATS_INCLUDE_DIRS}
    DEPENDENCIES
    ${LIBNATS_LIBRARIES}
    SOURCES
    NATS.cc
    Plugin.cc
    BIFS
    cluster_backend_nats.bif)
