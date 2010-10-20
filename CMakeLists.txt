##
## CMake Configuration
##

cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

# Prohibit in-source builds.
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" source_build)
if (source_build)
    message(FATAL_ERROR "In-source builds are not allowed\n."
        "Please create a separate build directory and invoke cmake from there.")
endif ()

# If the build configuration file does not exist, copy it over.
set(build_config BuildOptions.cmake)
find_file(build_config_file
    NAMES BuildOptions.cmake
    PATHS ${CMAKE_BINARY_DIR}
    DOC "Build configuration"
    NO_DEFAULT_PATH
    )
if (NOT build_config_file)
    message("No build configuration found, using default.")
    configure_file(${CMAKE_SOURCE_DIR}/${build_config}
                   ${CMAKE_BINARY_DIR}/${build_config}
                   )
endif ()
mark_as_advanced(build_config_file)

include(${CMAKE_BINARY_DIR}/${build_config})

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

##
## Project Configuration
##

project(Bro)

set(PACKAGE "Bro")
file(STRINGS "${CMAKE_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

add_definitions(-W -Wall -Wno-unused)

if (ENABLE_DEBUG)
    add_definitions(-DDEBUG -g)
endif ()

if (ENABLE_RELEASE)
    add_definitions(-O3)
endif ()

##
## Dependency Configuration
##

find_program(SED_EXE sed)
if (NOT SED_EXE)
    message(FATAL_ERROR "Could not find required dependency: sed")
else ()
    message(STATUS "Found sed: ${SED_EXE}")
endif ()

find_package(Perl REQUIRED)
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
find_package(PCAP REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(BIND REQUIRED)
include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${OPENSSL_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR})

# TODO: optional libmagic
# TODO: optional libGeoIP
# TODO: optional libz
# TODO: optional Endace's DAG tools
# TODO: optional Google perftools

##
## Configuration Checks/Tests
##

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

add_subdirectory(binpac)
add_subdirectory(src)
#add_subdirectory(aux)
#add_subdirectory(scripts)
#add_subdirectory(policy)
#add_subdirectory(doc)

##
## Build Summary
##

message(
    "\n====================|  Bro Build Summary  |====================="
    "\n"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nDatadir:           ${CMAKE_INSTALL_PREFIX}/${DATADIR}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nRelease mode:      ${ENABLE_RELEASE}"
    "\n"
    "\nBroccoli:          ${use_broccoli}"
    "\nBroctl:            ${use_broctl}"
    "\nGeoIP:             ${use_geoip}"
    "\nlibz:              ${use_libz}"
    "\nlibmagic:          ${use_libmagic}"
    "\nEndace:            ${use_endace}"
    "\nGoogle perftools:  ${summary_perftools}"
    "\n"
    "\n================================================================\n"
)
