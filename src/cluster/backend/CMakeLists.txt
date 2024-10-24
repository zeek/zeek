option(ENABLE_CLUSTER_BACKEND_ZEROMQ "Enable the ZeroMQ cluster backend" ON)
if (ENABLE_CLUSTER_BACKEND_ZEROMQ)
    add_subdirectory(zeromq)
endif ()

option(ENABLE_CLUSTER_BACKEND_NATS "Enable the NATS cluster backend" OFF)
if (ENABLE_CLUSTER_BACKEND_NATS)
    add_subdirectory(nats)
endif ()
