# - Try to find LibXML headers and libraries
#
# Usage of this module as follows:
#
#     find_package(LibXML)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibXML_ROOT_DIR  Set this variable to the root installation of
#                            LibXML if the module has problems finding 
#                            the proper installation path.
#
# Variables defined by this module:
#
#  LIBXML_FOUND              System has LibXML libs/headers
#  LibXML_LIBRARIES          The LibXML libraries
#  LibXML_INCLUDE_DIR        The location of LibXML headers

find_path(LibXML_ROOT_DIR
    NAMES include/libxml2/libxml/tree.h
)

find_library(LibXML_LIBRARIES
    NAMES xml2
    HINTS ${LibXML_ROOT_DIR}/lib
)

find_path(LibXML_INCLUDE_DIR
    NAMES libxml/tree.h
    HINTS ${LibXML_ROOT_DIR}/include/libxml2
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibXML DEFAULT_MSG
    LibXML_LIBRARIES
    LibXML_INCLUDE_DIR
)

mark_as_advanced(
    LibXML_ROOT_DIR
    LibXML_LIBRARIES
    LibXML_INCLUDE_DIR
)

