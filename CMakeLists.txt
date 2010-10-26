##
## CMake Configuration
##

cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

# Prohibit in-source builds.
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" source_build)
if (source_build)
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

##
## Project Configuration
##

project(Bro)

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

##
## Dependency Configuration
##

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

set(HAVE_LIBMAGIC false)
find_package(LibMagic)
if (LIBMAGIC_FOUND)
    set(HAVE_LIBMAGIC true)
endif ()

set(HAVE_LIBZ false)
find_package(ZLIB)
if (ZLIB_FOUND)
    set(HAVE_LIBZ true)
endif ()

set(USE_GEOIP false)
find_package(LibGeoIP)
if (LIBGEOIP_FOUND)
    set(USE_GEOIP true)
endif ()

set(USE_PERFTOOLS false)
if (ENABLE_PERFTOOLS)
    find_package(GooglePerftools)
    if (GOOGLEPERFTOOLS_FOUND)
        set(USE_PERFTOOLS true)
    endif ()
endif ()

include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${OPENSSL_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR}
                    ${BinPAC_INCLUDE_DIR}
                    ${LibMagic_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIR}
                    ${LibGeoIP_INCLUDE_DIR}
                    ${GooglePerftools_INCLUDE_DIR}
)

##
## Configuration Checks/Tests
##

file(STRINGS "${CMAKE_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

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

##
## Recurse on sub-directories
##

add_subdirectory(src)
add_subdirectory(policy)
#add_subdirectory(scripts)
#add_subdirectory(doc)
#add_subdirectory(aux)

##
## Build Summary
##

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
