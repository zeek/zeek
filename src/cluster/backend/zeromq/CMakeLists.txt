list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(ZeroMQ REQUIRED)

zeek_add_plugin(
    Zeek Cluster_Backend_ZeroMQ
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${ZeroMQ_INCLUDE_DIRS}
    DEPENDENCIES ${ZeroMQ_LIBRARIES}
    SOURCES Plugin.cc ZeroMQ-Proxy.cc ZeroMQ.cc
    BIFS cluster_backend_zeromq.bif)
