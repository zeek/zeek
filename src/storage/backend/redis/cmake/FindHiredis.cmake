include(FindPackageHandleStandardArgs)

find_library(
    HIREDIS_LIBRARY NAMES "libhiredis${CMAKE_SHARED_LIBRARY_SUFFIX}"
                          "libhiredis${CMAKE_STATIC_LIBRARY_SUFFIX}" HINTS ${HIREDIS_ROOT_DIR}/lib)

find_path(HIREDIS_INCLUDE_DIR NAMES hiredis/hiredis.h HINTS ${HIREDIS_ROOT_DIR}/include)

find_package_handle_standard_args(Hiredis FOUND_VAR HIREDIS_FOUND REQUIRED_VARS HIREDIS_LIBRARY
                                                                                HIREDIS_INCLUDE_DIR)

if (HIREDIS_FOUND)

    # The hiredis library must be at least v1.0.0 to have all of the API bits that
    # we need.  We can scrape that out of the header.
    file(STRINGS "${HIREDIS_INCLUDE_DIR}/hiredis/hiredis.h" HIREDIS_MAJOR_VERSION_H
         REGEX "^#define HIREDIS_MAJOR [0-9]+$")
    file(STRINGS "${HIREDIS_INCLUDE_DIR}/hiredis/hiredis.h" HIREDIS_MINOR_VERSION_H
         REGEX "^#define HIREDIS_MINOR [0-9]+$")
    file(STRINGS "${HIREDIS_INCLUDE_DIR}/hiredis/hiredis.h" HIREDIS_PATCH_VERSION_H
         REGEX "^#define HIREDIS_PATCH [0-9]+$")
    string(REGEX REPLACE "^.*MAJOR ([0-9]+)$" "\\1" HIREDIS_MAJOR_VERSION
                         "${HIREDIS_MAJOR_VERSION_H}")
    string(REGEX REPLACE "^.*MINOR ([0-9]+)$" "\\1" HIREDIS_MINOR_VERSION
                         "${HIREDIS_MINOR_VERSION_H}")
    string(REGEX REPLACE "^.*PATCH ([0-9]+)$" "\\1" HIREDIS_PATCH_VERSION
                         "${HIREDIS_PATCH_VERSION_H}")

    set(HIREDIS_VERSION
        "${HIREDIS_MAJOR_VERSION}.${HIREDIS_MINOR_VERSION}.${HIREDIS_PATCH_VERSION}")

    if (HIREDIS_VERSION VERSION_LESS "1.1.0")
        message(
            STATUS "Hiredis library version ${HIREDIS_VERSION} is too old, need v1.1.0 or later.")
        unset(HIREDIS_FOUND)

    else ()
        set(HIREDIS_LIBRARIES ${HIREDIS_LIBRARY})
        set(HIREDIS_INCLUDE_DIRS ${HIREDIS_INCLUDE_DIR})
        set(HIREDIS_FOUND ${HIREDIS_FOUND})
    endif ()
endif ()
