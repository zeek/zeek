# - Try to find netmap includes.
#
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  NETMAP_ROOT_DIR           Set this variable to the root installation of
#                            netmap if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  NETMAP_FOUND              System has netmap API files.
#  NETMAP_INCLUDE_DIR        The netmap include directory.

find_path(NETMAP_ROOT_DIR
    NAMES sys/net/netmap_user.h
)

find_path(NETMAP_INCLUDE_DIR
    NAMES sys/net/netmap_user.h
    HINTS ${NETMAP_ROOT_DIR}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Netmap DEFAULT_MSG
    NETMAP_INCLUDE_DIR
)

mark_as_advanced(
    NETMAP_ROOT_DIR
    NETMAP_INCLUDE_DIR
)
