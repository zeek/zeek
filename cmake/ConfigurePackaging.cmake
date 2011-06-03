# A collection of macros to assist in configuring CMake/Cpack
# source and binary packaging

# Sets CPack version variables by splitting the first macro argument
# using "." as a delimiter.  If the length of the split list is
# greater than 2, all remaining elements are tacked on to the patch
# level version.  Not that the version set by the macro is internal
# to binary packaging, the file name of our package will reflect the
# exact version number.
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

    if (APPLE)
        # Mac PackageMaker package requires only numbers in the versioning
        string(REGEX REPLACE "[_a-zA-Z-]" "" CPACK_PACKAGE_VERSION_MAJOR
               ${CPACK_PACKAGE_VERSION_MAJOR})
        string(REGEX REPLACE "[_a-zA-Z-]" "" CPACK_PACKAGE_VERSION_MINOR
               ${CPACK_PACKAGE_VERSION_MINOR})
        if (CPACK_PACKAGE_VERSION_PATCH)
            string(REGEX REPLACE "[_a-zA-Z-]" "" CPACK_PACKAGE_VERSION_PATCH
                   ${CPACK_PACKAGE_VERSION_PATCH})
        endif ()
    endif ()

    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        # RPM version accepts letters, but not dashes.
        string(REGEX REPLACE "[-]" "" CPACK_PACKAGE_VERSION_MAJOR
               ${CPACK_PACKAGE_VERSION_MAJOR})
        string(REGEX REPLACE "[-]" "" CPACK_PACKAGE_VERSION_MINOR
               ${CPACK_PACKAGE_VERSION_MINOR})
        if (CPACK_PACKAGE_VERSION_PATCH)
            string(REGEX REPLACE "[-]" "" CPACK_PACKAGE_VERSION_PATCH
                   ${CPACK_PACKAGE_VERSION_PATCH})
        endif ()
    endif ()

    # Minimum supported OS X version
    set(CPACK_OSX_PACKAGE_VERSION 10.5)
endmacro(SetPackageVersion)

# Sets the list of desired package types to be created by the make
# package target.  A .tar.gz is only made for source packages, and 
# binary pacakage format depends on the operating system:
#
# Darwin - PackageMaker
# Linux - RPM if the platform has rpmbuild installed
#         DEB if the platform has dpkg-shlibdeps installed
#
# CPACK_GENERATOR is set by this macro
# CPACK_SOURCE_GENERATOR is set by this macro
macro(SetPackageGenerators)
    set(CPACK_SOURCE_GENERATOR TGZ)
    #set(CPACK_GENERATOR TGZ)
    if (APPLE)
        list(APPEND CPACK_GENERATOR PackageMaker)
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        find_program(RPMBUILD_EXE rpmbuild)
        find_program(DPKGSHLIB_EXE dpkg-shlibdeps)
        if (RPMBUILD_EXE)
            set(CPACK_GENERATOR ${CPACK_GENERATOR} RPM)
        endif ()
        if (DPKGSHLIB_EXE)
            set(CPACK_GENERATOR ${CPACK_GENERATOR} DEB)
            set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS true)
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
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/MAC_PACKAGE_INTRO
                   ${CMAKE_CURRENT_BINARY_DIR}/MAC_PACKAGE_INTRO.txt)

    set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_BINARY_DIR}/README.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_BINARY_DIR}/COPYING.txt)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_BINARY_DIR}/README.txt)
    set(CPACK_RESOURCE_FILE_WELCOME
        ${CMAKE_CURRENT_BINARY_DIR}/MAC_PACKAGE_INTRO.txt)

    set(CPACK_RPM_PACKAGE_LICENSE "BSD")
endmacro(SetPackageMetadata)

# Sets pre and post install scripts for PackageMaker packages.
# The main functionality that such scripts offer is a way to make backups
# of "configuration" files that a user may have modified.
# Note that RPMs already have a robust mechanism for dealing with
# user-modified files, so we do not need this additional functionality
macro(SetPackageInstallScripts VERSION)

    if (INSTALLED_CONFIG_FILES)
        # Remove duplicates from the list of installed config files
        separate_arguments(INSTALLED_CONFIG_FILES)
        list(REMOVE_DUPLICATES INSTALLED_CONFIG_FILES)
        # Space delimit the list again
        foreach (_file ${INSTALLED_CONFIG_FILES})
            set(_tmp "${_tmp} ${_file}")
        endforeach ()
        set(INSTALLED_CONFIG_FILES "${_tmp}" CACHE STRING "" FORCE)
    endif ()

    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        # DEB packages can automatically handle configuration files
        # if provided in a "conffiles" file in the packaging
        set(conffiles_file ${CMAKE_CURRENT_BINARY_DIR}/conffiles)
        if (INSTALLED_CONFIG_FILES)
            string(REPLACE " " ";" conffiles ${INSTALLED_CONFIG_FILES})
        endif ()
        file(WRITE ${conffiles_file} "")
        foreach (_file ${conffiles})
            file(APPEND ${conffiles_file} "${_file}\n")
        endforeach ()

        list(APPEND CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
            ${CMAKE_CURRENT_BINARY_DIR}/conffiles)

        # RPMs don't need any explicit direction regarding config files.

        # Leaving the set of installed config files empty will just
        # bypass the logic in the default pre/post install scripts and let
        # the RPMs/DEBs do their own thing (regarding backups, etc.)
        # when upgrading packages.
        set(INSTALLED_CONFIG_FILES "")
    endif ()

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_preinstall.sh.in)
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_preinstall.sh.in
            ${CMAKE_CURRENT_BINARY_DIR}/package_preinstall.sh
            @ONLY)
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_preinstall.sh.in
            ${CMAKE_CURRENT_BINARY_DIR}/preinst
            @ONLY)
        set(CPACK_PREFLIGHT_SCRIPT
            ${CMAKE_CURRENT_BINARY_DIR}/package_preinstall.sh)
        set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE
            ${CMAKE_CURRENT_BINARY_DIR}/package_preinstall.sh)
        list(APPEND CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
            ${CMAKE_CURRENT_BINARY_DIR}/preinst)
    endif ()

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_postupgrade.sh.in)
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_postupgrade.sh.in
            ${CMAKE_CURRENT_BINARY_DIR}/package_postupgrade.sh
            @ONLY)
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_postupgrade.sh.in
            ${CMAKE_CURRENT_BINARY_DIR}/postinst
            @ONLY)
        set(CPACK_POSTUPGRADE_SCRIPT
            ${CMAKE_CURRENT_BINARY_DIR}/package_postupgrade.sh)
        set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE
            ${CMAKE_CURRENT_BINARY_DIR}/package_postupgrade.sh)
        list(APPEND CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
            ${CMAKE_CURRENT_BINARY_DIR}/postinst)
    endif ()
endmacro(SetPackageInstallScripts)

# Main macro to configure all the packaging options
macro(ConfigurePackaging _version)
    SetPackageVersion(${_version})
    SetPackageGenerators()
    SetPackageFileName(${_version})
    SetPackageMetadata()
    SetPackageInstallScripts(${_version})

    set(CPACK_SET_DESTDIR true)
    set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

    # add default files/directories to ignore for source package
    # user may specify others via configure script
    list(APPEND CPACK_SOURCE_IGNORE_FILES ${CMAKE_BINARY_DIR} ".git")

    include(CPack)
endmacro(ConfigurePackaging)
