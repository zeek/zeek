########################################################################
## CMake Configuration

cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

# Prohibit in-source builds.
if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed. Please use "
                        "./configure to choose a build directory and "
                        "initialize the build configuration.")
endif ()

find_file(build_options_file
    NAMES BuildOptions.cmake
    PATHS ${CMAKE_BINARY_DIR}
    DOC "Build Options"
    NO_DEFAULT_PATH
    )
if (NOT build_options_file)
    message(FATAL_ERROR "Build options file not found, please use "
                        "${CMAKE_SOURCE_DIR}/configure to generate one.")
endif ()
mark_as_advanced(build_config_file)

include(${build_options_file})

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

########################################################################
## Project/Build Configuration

project(Bro)

file(STRINGS "${CMAKE_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if (ENABLE_DEBUG AND ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
elseif (ENABLE_DEBUG AND NOT ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE Debug)
elseif (NOT ENABLE_DEBUG AND ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(EXTRA_COMPILE_FLAGS "-Wall -Wno-unused")

if (ENABLE_DEBUG)
    set(EXTRA_COMPILE_FLAGS "${EXTRA_COMPILE_FLAGS} -DDEBUG")
endif ()

# Compiler flags may already exist in CMake cache (e.g. when specifying
# CFLAGS environment variable before running cmake for the the first time)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_COMPILE_FLAGS}")

########################################################################
## Dependency Configuration

# Check cache value first to avoid displaying "Found sed" messages everytime
if (NOT SED_EXE)
    find_program(SED_EXE sed)
    if (NOT SED_EXE)
        message(FATAL_ERROR "Could not find required dependency: sed")
    else ()
        message(STATUS "Found sed: ${SED_EXE}")
    endif ()
endif ()

find_package(Perl REQUIRED)
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
find_package(PCAP REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(BIND REQUIRED)
find_package(BinPAC REQUIRED)

include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${OpenSSL_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR}
                    ${BinPAC_INCLUDE_DIR}
)

# Optional Dependencies

set(HAVE_LIBMAGIC false)
find_package(LibMagic)
if (LIBMAGIC_FOUND)
    set(HAVE_LIBMAGIC true)
    include_directories(BEFORE ${LibMagic_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibMagic_LIBRARY})
endif ()

set(HAVE_LIBZ false)
find_package(ZLIB)
if (ZLIB_FOUND)
    set(HAVE_LIBZ true)
    include_directories(BEFORE ${ZLIB_INCLUDE_DIR})
    list(APPEND OPTLIBS ${ZLIB_LIBRARY})
endif ()

set(USE_GEOIP false)
find_package(LibGeoIP)
if (LIBGEOIP_FOUND)
    set(USE_GEOIP true)
    include_directories(BEFORE ${LibGeoIP_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibGeoIP_LIBRARY})
endif ()

set(USE_PERFTOOLS false)
if (ENABLE_PERFTOOLS)
    find_package(GooglePerftools)
    if (GOOGLEPERFTOOLS_FOUND)
        set(USE_PERFTOOLS true)
        include_directories(BEFORE ${GooglePerftools_INCLUDE_DIR})
        list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
    endif ()
endif ()

########################################################################
## System Introspection

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

include(OSSpecific)
include(CheckTypes)
include(CheckHeaders)
include(CheckFunctions)
include(MiscTests)
include(PCAPTests)
include(OpenSSLTests)
include(CheckNameserCompat)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

########################################################################
## Recurse on sub-directories

add_subdirectory(src)
add_subdirectory(policy)
#add_subdirectory(scripts)
#add_subdirectory(doc)

if (INSTALL_AUXTOOLS)
    add_subdirectory(aux)
endif ()

########################################################################
## Packaging Setup

include(SetPackageVersion)
SetPackageVersion(${VERSION})
include(SetPackageGenerators)
include(SetPackageFileName)

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

include(CPack)

########################################################################
## Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n====================|  Bro Build Summary  |====================="
    "\n"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nDatadir:           ${DATADIR}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nRelease mode:      ${ENABLE_RELEASE}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nBroccoli:          ${use_broccoli}"
    "\nBroctl:            ${use_broctl}"
    "\nGeoIP:             ${USE_GEOIP}"
    "\nlibz:              ${HAVE_LIBZ}"
    "\nlibmagic:          ${HAVE_LIBMAGIC}"
    "\nGoogle perftools:  ${USE_PERFTOOLS}"
    "\n"
    "\n================================================================\n"
)
