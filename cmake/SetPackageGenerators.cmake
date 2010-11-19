# Sets the list of desired package types to be created by the make
# package target.  A .tar.gz is always made, and depending on the
# operating system, more are added:
#
# Darwin - PackageMaker
# Linux - RPM if the platform has rpmbuild installed
#         DEB is ommitted because CPack does not give enough
#         control over how the package is created and lacks support
#         for automatic dependency detection.
#         
#
# CPACK_GENERATOR is set by this module

set(CPACK_GENERATOR TGZ)
set(CPACK_SOURCE_GENERATOR TGZ)
if (APPLE)
    list(APPEND CPACK_GENERATOR PackageMaker)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    find_program(RPMBUILD_EXE rpmbuild)
    if (RPMBUILD_EXE)
        set(CPACK_GENERATOR ${CPACK_GENERATOR} RPM)
    endif ()
endif ()
