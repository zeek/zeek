# - Try to find GooglePerftools headers and libraries
#
# Usage of this module as follows:
#
#     find_package(GooglePerftools)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  GooglePerftools_ROOT_DIR  Set this variable to the root installation of
#                            GooglePerftools if the module has problems finding 
#                            the proper installation path.
#
# Variables defined by this module:
#
#  GOOGLEPERFTOOLS_FOUND              System has GooglePerftools libs/headers
#  GooglePerftools_LIBRARIES          The GooglePerftools libraries
#  GooglePerftools_INCLUDE_DIR        The location of GooglePerftools headers

find_path(GooglePerftools_ROOT_DIR
    NAMES include/google/heap-profiler.h
)

find_library(GooglePerftools_LIBRARIES
    NAMES tcmalloc
    HINTS ${GooglePerftools_ROOT_DIR}/lib
)

find_path(GooglePerftools_INCLUDE_DIR
    NAMES google/heap-profiler.h
    HINTS ${GooglePerftools_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GooglePerftools DEFAULT_MSG
    GooglePerftools_LIBRARIES
    GooglePerftools_INCLUDE_DIR
)

mark_as_advanced(
    GooglePerftools_ROOT_DIR
    GooglePerftools_LIBRARIES
    GooglePerftools_INCLUDE_DIR
)
