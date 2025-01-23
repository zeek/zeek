list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Hiredis)

if (HIREDIS_FOUND)

    zeek_add_plugin(
        Zeek
        Storage_Backend_Redis
        INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${HIREDIS_INCLUDE_DIRS}
        DEPENDENCIES
        ${HIREDIS_LIBRARIES}
        SOURCES
        Plugin.cc
        Redis.cc)

else ()
    message(STATUS "Hiredis library not found. Redis storage backend will not be built.")
endif ()
