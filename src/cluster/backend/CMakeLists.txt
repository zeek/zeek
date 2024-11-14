option(ENABLE_CLUSTER_BACKEND_ZEROMQ "Enable the ZeroMQ cluster backend" ON)
if (ENABLE_CLUSTER_BACKEND_ZEROMQ)
    add_subdirectory(zeromq)
endif ()
