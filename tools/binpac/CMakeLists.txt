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

project(BinPAC)

set(CMAKE_C_FLAGS "-W -Wall -Wno-unused")
set(CMAKE_CXX_FLAGS "-W -Wall -Wno-unused")

if (ENABLE_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif ()

if (ENABLE_RELEASE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif ()

##
## Dependency Configuration
##

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

##
## Configuration Checks/Tests
##

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" BINPAC_VERSION LIMIT_COUNT 1)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

##
## Recuse on sub-directories
##

add_subdirectory(lib)
add_subdirectory(src)

##
## Build Summary
##

if (BinPAC_SKIP_INSTALL)
    set(binpac_install_summary "Install skipped")
else ()
    set(binpac_install_summary "${CMAKE_INSTALL_PREFIX}")
endif ()

message(
    "\n==================|  BinPAC Build Summary  |===================="
    "\n"
    "\nInstall prefix:    ${binpac_install_summary}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nRelease mode:      ${ENABLE_RELEASE}"
    "\n"
    "\nCFLAGS:            ${CMAKE_C_FLAGS}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS}"
    "\n"
    "\n================================================================\n"
)
