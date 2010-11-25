# Sets CPACK_PACKAGE_FILE name in the following format:
#
# <project_name>-<version>-<OS/platform>-<arch>
#
# The version must already be set in the VERSION variable

set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-${CMAKE_SYSTEM_NAME}")
if (APPLE)
    # Only Intel-based Macs are supported.  CMAKE_SYSTEM_PROCESSOR may
    # return the confusing 'i386' if running a 32-bit kernel, but chances
    # are the binary is x86_64 (or more generally 'Intel') compatible.
    set(arch "Intel")
else ()
    set (arch ${CMAKE_SYSTEM_PROCESSOR})
endif ()

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-${arch}")
