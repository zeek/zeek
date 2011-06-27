# - Try to find DataSeries headers and libraries
#
# Usage of this module as follows:
#
#     find_package(DataSeries)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  DataSeries_ROOT_DIR  Set this variable to the root installation of
#                            DataSeries if the module has problems finding 
#                            the proper installation path.
#
# Variables defined by this module:
#
#  DATASERIES_FOUND              System has DataSeries libs/headers
#  DataSeries_LIBRARIES          The DataSeries libraries
#  DataSeries_INCLUDE_DIR        The location of DataSeries headers

find_path(DataSeries_ROOT_DIR
    NAMES include/DataSeries/Extent.hpp
)

find_library(DataSeries_LIBRARIES
    NAMES DataSeries
    HINTS ${DataSeries_ROOT_DIR}/lib
)

find_path(DataSeries_INCLUDE_DIR
    NAMES DataSeries/Extent.hpp
    HINTS ${DataSeries_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DataSeries DEFAULT_MSG
    DataSeries_LIBRARIES
    DataSeries_INCLUDE_DIR
)

mark_as_advanced(
    DataSeries_ROOT_DIR
    DataSeries_LIBRARIES
    DataSeries_INCLUDE_DIR
)

