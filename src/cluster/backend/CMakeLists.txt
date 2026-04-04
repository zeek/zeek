# Default to building ZeroMQ, but add an option that allows it to be disabled
# via CMake.
option(ENABLE_CLUSTER_BACKEND_ZEROMQ "Enable the ZeroMQ cluster backend" ON)

if (ENABLE_CLUSTER_BACKEND_ZEROMQ)

    if (MSVC)
        find_package(ZeroMQ CONFIG REQUIRED)
    else ()
        list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/zeromq/cmake")

        # Require ZeroMQ version 4.3.0 released in late 2018. The proxy_steerable()
        # STATISTICS command was a draft API before that, but we'd like to use it.
        find_package(ZeroMQ 4.3.0 REQUIRED)
    endif ()

    add_subdirectory(zeromq)
endif ()

add_subdirectory(none)
