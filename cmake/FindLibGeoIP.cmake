# - Try to find GeoIP headers and libraries
#
# Usage of this module as follows:
#
#     find_package(LibGeoIP)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibGeoIP_ROOT_DIR         Set this variable to the root installation of
#                            libGeoIP if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  LIBGEOIP_FOUND              System has GeoIP libraries and headers
#  LibGeoIP_LIBRARY            The GeoIP library
#  LibGeoIP_INCLUDE_DIR        The location of GeoIP headers

find_path(LibGeoIP_ROOT_DIR
    NAMES include/GeoIPCity.h
)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # the static version of the library is preferred on OS X for the
    # purposes of making packages (libGeoIP doesn't ship w/ OS X)
    set(libgeoip_names libGeoIp.a GeoIP)
else ()
    set(libgeoip_names GeoIP)
endif ()

find_library(LibGeoIP_LIBRARY
    NAMES ${libgeoip_names}
    HINTS ${LibGeoIP_ROOT_DIR}/lib
)

find_path(LibGeoIP_INCLUDE_DIR
    NAMES GeoIPCity.h
    HINTS ${LibGeoIP_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibGeoIP DEFAULT_MSG
    LibGeoIP_LIBRARY
    LibGeoIP_INCLUDE_DIR
)

mark_as_advanced(
    LibGeoIP_ROOT_DIR
    LibGeoIP_LIBRARY
    LibGeoIP_INCLUDE_DIR
)
