list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Hiredis)

# Default to building Reids only if the hiredis library was found.
#
# If a user enabled the backend explicitly (-D ENABLE_STORAGE_BACKEND_REDIS:bool=ON),
# but hiredis wasn't found, hard bail.
option(ENABLE_STORAGE_BACKEND_REDIS "Enable the Redis storage backend" ${HIREDIS_FOUND})

if (ENABLE_STORAGE_BACKEND_REDIS)
    if (NOT HIREDIS_FOUND)
        message(STATUS "ENABLE_STORAGE_BACKEND_REDIS set, but hiredis library not available.")
    endif ()

    zeek_add_plugin(
        Zeek Storage_Backend_Redis
        INCLUDE_DIRS ${HIREDIS_INCLUDE_DIRS}
        DEPENDENCIES ${HIREDIS_LIBRARIES}
        SOURCES Plugin.cc Redis.cc)

endif ()
