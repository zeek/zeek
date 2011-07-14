# - Try to find Lintel headers and libraries
#
# Usage of this module as follows:
#
#     find_package(Lintel)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  Lintel_ROOT_DIR  Set this variable to the root installation of
#                            Lintel if the module has problems finding 
#                            the proper installation path.
#
# Variables defined by this module:
#
#  LINTEL_FOUND              System has Lintel libs/headers
#  Lintel_LIBRARIES          The Lintel libraries
#  Lintel_INCLUDE_DIR        The location of Lintel headers

find_path(Lintel_ROOT_DIR
    NAMES include/Lintel/LintelVersion.hpp
)

find_library(Lintel_LIBRARIES
    NAMES Lintel
    HINTS ${Lintel_ROOT_DIR}/lib
)

find_path(Lintel_INCLUDE_DIR
    NAMES Lintel/LintelVersion.hpp
    HINTS ${Lintel_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Lintel DEFAULT_MSG
    Lintel_LIBRARIES
    Lintel_INCLUDE_DIR
)

mark_as_advanced(
    Lintel_ROOT_DIR
    Lintel_LIBRARIES
    Lintel_INCLUDE_DIR
)
