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

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
find_package(PCAP REQUIRED)
include_directories(BEFORE ${PCAP_INCLUDE_DIR})

# TODO: find bind8 lib?
# TODO: require OpenSSL
# TODO: optional libmagic
# TODO: optional libGeoIP
# TODO: optional libz
# TODO: optional Endace's DAG tools
# TODO: optional Google perftools
# TODO: compiler warning flags

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

include(OSSpecific)
include(CheckTypes)
include(CheckHeaders)
include(CheckFunctions)
include(MiscTests)
include(PCAPTests)
#TODO: use/integrate find_package(OpenSSL)
include(OpenSSLTests)

#TODO: NB_DNS tests
set(HAVE_NB_DNS ${USE_NB_DNS})
set(HAVE_ASYNC_DNS ${USE_NB_DNS}) #TODO: should make consistent w/ HAVE_NB_DNS

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR})

add_definitions(-DHAVE_CONFIG_H)

add_subdirectory(binpac)
add_subdirectory(src)
#add_subdirectory(aux)
#add_subdirectory(scripts)
#add_subdirectory(policy)
#add_subdirectory(doc)
