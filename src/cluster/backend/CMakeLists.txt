# Default to building ZeroMQ, but add an option that allows it to be disabled
# via CMake.
option(ENABLE_CLUSTER_BACKEND_ZEROMQ "Enable the ZeroMQ cluster backend" ON)

if (ENABLE_CLUSTER_BACKEND_ZEROMQ)

    if (MSVC)
        find_package(ZeroMQ CONFIG REQUIRED)
    else ()
        list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/zeromq/cmake")
        find_package(ZeroMQ REQUIRED)
    endif ()

    if (NOT ZeroMQ_FOUND)
        message(FATAL_ERROR "ENABLE_CLUSTER_BACKEND_ZEROMQ set, but ZeroMQ library not available")
    endif ()

    add_subdirectory(zeromq)
endif ()

add_subdirectory(none)
