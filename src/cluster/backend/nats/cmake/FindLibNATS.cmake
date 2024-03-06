include(FindPackageHandleStandardArgs)

find_library(LibNATS_LIBRARY NAMES libnats.so libnats_static.a HINTS ${LIBNATS_ROOT_DIR}/lib)

find_path(LibNATS_INCLUDE_DIR NAMES nats.h HINTS ${LIBNATS_ROOT_DIR}/include)

find_package_handle_standard_args(LibNATS FOUND_VAR LibNATS_FOUND REQUIRED_VARS LibNATS_LIBRARY
                                                                                LibNATS_INCLUDE_DIR)

set(LIBNATS_LIBRARIES ${LibNATS_LIBRARY} ${LibPROTOBUFC_LIBRARY})
set(LIBNATS_INCLUDE_DIRS ${LibNATS_INCLUDE_DIR})
set(LIBNATS_FOUND ${LibNATS_FOUND})
