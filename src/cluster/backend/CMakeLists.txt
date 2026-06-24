list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/zeromq/cmake")

# Default to building ZeroMQ only if ZeroMQ was found.
#
# If a user enabled the cluster backend explicitly (-D ENABLE_CLUSTER_BACKEND_ZEROMQ:bool=ON),
# but ZeroMQ wasn' found, hard bail.
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
