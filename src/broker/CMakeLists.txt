zeek_add_subdir_library(
    comm
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
    Data.cc
    Manager.cc
    Store.cc
    BIFS
    comm.bif
    data.bif
    messaging.bif
    store.bif)

# Small plugin shim to make the CLUSTER_BACKEND_BROKER enum value available.
zeek_add_plugin(Zeek Cluster_Backend_Broker SOURCES Plugin.cc)
