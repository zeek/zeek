zeek_add_subdir_library(
    storage
    SOURCES
    Manager.cc
    Backend.cc
    Component.cc
    ReturnCode.cc
    BIFS
    storage.bif
    storage-async.bif
    storage-events.bif
    storage-sync.bif)

add_subdirectory(backend)
add_subdirectory(serializer)
