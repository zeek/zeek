# A collection of macros to assist in configuring CMake/Cpack
# source and binary packaging

# Sets CPack version variables by splitting the first macro argument
# using "." as a delimiter.  If the length of the split list is
# greater than 2, all remaining elements are tacked on to the patch
# level version.
macro(SetPackageVersion _version)
    string(REPLACE "." " " version_numbers ${_version})
    separate_arguments(version_numbers)

    list(GET version_numbers 0 CPACK_PACKAGE_VERSION_MAJOR)
    list(REMOVE_AT version_numbers 0)
    list(GET version_numbers 0 CPACK_PACKAGE_VERSION_MINOR)
    list(REMOVE_AT version_numbers 0)
    list(LENGTH version_numbers version_length)

    while (version_length GREATER 0)
        list(GET version_numbers 0 patch_level)
        if (CPACK_PACKAGE_VERSION_PATCH)
            set(CPACK_PACKAGE_VERSION_PATCH
                "${CPACK_PACKAGE_VERSION_PATCH}.${patch_level}")
        else ()
            set(CPACK_PACKAGE_VERSION_PATCH ${patch_level})
        endif ()
        list(REMOVE_AT version_numbers 0)
        list(LENGTH version_numbers version_length)
    endwhile ()
endmacro(SetPackageVersion)

# Sets the list of desired package types to be created by the make
# package target.  A .tar.gz is only made for source packages, and 
# binary pacakage format depends on the operating system:
#
# Darwin - PackageMaker
# Linux - RPM if the platform has rpmbuild installed
#         DEB is ommitted because CPack does not give enough
#         control over how the package is created and lacks support
#         for automatic dependency detection.
#         
#
# CPACK_GENERATOR is set by this macro
# CPACK_SOURCE_GENERATOR is set by this macro
macro(SetPackageGenerators)
    set(CPACK_SOURCE_GENERATOR TGZ)
    if (APPLE)
        list(APPEND CPACK_GENERATOR PackageMaker)
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        find_program(RPMBUILD_EXE rpmbuild)
        if (RPMBUILD_EXE)
            set(CPACK_GENERATOR ${CPACK_GENERATOR} RPM)
        endif ()
    endif ()
endmacro(SetPackageGenerators)

# Sets CPACK_PACKAGE_FILE_NAME in the following format:
#
# <project_name>-<version>-<OS/platform>-<arch>
#
# and CPACK_SOURCE_PACKAGE_FILE_NAME as:
#
# <project_name>-<version>
macro(SetPackageFileName _version)
    if (PACKAGE_NAME_PREFIX)
        set(CPACK_PACKAGE_FILE_NAME "${PACKAGE_NAME_PREFIX}-${_version}")
        set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PACKAGE_NAME_PREFIX}-${_version}")
    else ()
        set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${_version}")
        set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${_version}")
    endif ()

    set(CPACK_PACKAGE_FILE_NAME
        "${CPACK_PACKAGE_FILE_NAME}-${CMAKE_SYSTEM_NAME}")

    if (APPLE)
        # Only Intel-based Macs are supported.  CMAKE_SYSTEM_PROCESSOR may
        # return the confusing 'i386' if running a 32-bit kernel, but chances
        # are the binary is x86_64 (or more generally 'Intel') compatible.
        set(arch "Intel")
    else ()
        set (arch ${CMAKE_SYSTEM_PROCESSOR})
    endif ()

    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-${arch}")
endmacro(SetPackageFileName)

# Sets up binary package metadata
macro(SetPackageMetadata)
    set(CPACK_PACKAGE_VENDOR "Lawrence Berkeley National Laboratory")
    set(CPACK_PACKAGE_CONTACT "info@bro-ids.org")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
        "The Bro Network Intrusion Detection System")

    # CPack may enforce file name extensions for certain package generators
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/README
                   ${CMAKE_CURRENT_BINARY_DIR}/README.txt
                    COPYONLY)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/COPYING
                   ${CMAKE_CURRENT_BINARY_DIR}/COPYING.txt
                    COPYONLY)

    set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_BINARY_DIR}/README.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_BINARY_DIR}/COPYING.txt)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_BINARY_DIR}/README.txt)
    set(CPACK_RESOURCE_FILE_WELCOME ${CMAKE_CURRENT_BINARY_DIR}/README.txt)
endmacro(SetPackageMetadata)

# Determines the right install location/prefix for binary packages
macro(SetPackageInstallLocation)
    if (APPLE)
        # /usr prefix is hardcoded for PackageMaker generator, but that
        # directory may not be ideal for OS X (it's tricky to remove
        # packages installed there).  So instead we rely on CMAKE_INSTALL_PREFIX
        # and set the following variable to workaround the hardcoded /usr prefix
        set(CPACK_PACKAGING_INSTALL_PREFIX "/")
        set(CPACK_PACKAGE_DEFAULT_LOCATION ${CMAKE_INSTALL_PREFIX})
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        # A prefix of /usr would follow Filesystem Hierarchy Standard.
        # For RPM packaging by CPack, /usr should be a default, but
        # CMAKE_INSTALL_PREFIX also needs to be set to /usr so that
        # the default BROPATH is set right at build time
        set(CPACK_RPM_PACKAGE_LICENSE "BSD")
    endif ()
endmacro(SetPackageInstallLocation)

# Main macro to configure all the packaging options
macro(ConfigurePackaging _version)
    # If this CMake project is a sub-project of another, we will not
    # configure the packaging because CPack will fail in the case that
    # the parent project has already configured packaging
    if (NOT "${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
        return()
    endif ()

    SetPackageVersion(${_version})
    SetPackageGenerators()
    SetPackageFileName(${_version})
    SetPackageMetadata()
    SetPackageInstallLocation()

    # add default files/directories to ignore for source package
    # user may specify others via configure script
    list(APPEND CPACK_SOURCE_IGNORE_FILES ${CMAKE_BINARY_DIR} ".git")

    include(CPack)
endmacro(ConfigurePackaging)
