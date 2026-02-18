list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(PostgreSQL_ADDITIONAL_VERSIONS "18")
find_package(PostgreSQL)

# Default to building PostgreSQL only if the PostgreSQL library was found.
#
# If a user enabled the backend explicitly (-D ENABLE_STORAGE_BACKEND_POSTGRESQL:bool=ON),
# but PostgreSQL wasn't found, hard bail.
option(ENABLE_STORAGE_BACKEND_POSTGRESQL "Enable the PostgreSQL storage backend"
       ${PostgreSQL_FOUND})

if (ENABLE_STORAGE_BACKEND_POSTGRESQL)
    if (NOT PostgreSQL_FOUND)
        message(
            STATUS "ENABLE_STORAGE_BACKEND_POSTGRESQL set, but PostgreSQL library not available.")
    endif ()

    zeek_add_plugin(
        Zeek Storage_Backend_PostgreSQL
        INCLUDE_DIRS ${PostgreSQL_INCLUDE_DIRS}
        DEPENDENCIES ${PostgreSQL_LIBRARIES}
        SOURCES PostgreSQL.cc Plugin.cc)

endif ()
