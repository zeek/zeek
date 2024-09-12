include(FindPackageHandleStandardArgs)

find_library(
    hiredis_LIBRARY NAMES "libhiredis${CMAKE_SHARED_LIBRARY_SUFFIX}"
                          "libhiredis${CMAKE_STATIC_LIBRARY_SUFFIX}" HINTS ${HIREDIS_ROOT_DIR}/lib)

find_path(hiredis_INCLUDE_DIR NAMES nats.h HINTS ${HIREDIS_ROOT_DIR}/include)

find_package_handle_standard_args(hiredis FOUND_VAR hiredis_FOUND REQUIRED_VARS hiredis_LIBRARY
                                                                                hiredis_INCLUDE_DIR)

set(HIREDIS_LIBRARIES ${hiredis_LIBRARY})
set(HIREDIS_INCLUDE_DIRS ${hiredis_INCLUDE_DIR})
set(HIREDIS_FOUND ${hiredis_FOUND})
