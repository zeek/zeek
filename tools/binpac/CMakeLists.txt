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

project(BinPAC)

if (ENABLE_DEBUG AND ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
elseif (ENABLE_DEBUG AND NOT ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE Debug)
elseif (NOT ENABLE_DEBUG AND ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# don't set extra compile flags again if already declared in this scope
# (i.e. this project is included from Bro)
if (NOT EXTRA_COMPILE_FLAGS)
    set(EXTRA_COMPILE_FLAGS "-Wall -Wno-unused")

    if (ENABLE_DEBUG)
        set(EXTRA_COMPILE_FLAGS "${EXTRA_COMPILE_FLAGS} -DDEBUG")
    endif ()

    # Compiler flags may already exist in CMake cache (e.g. when specifying
    # CFLAGS environment variable before running cmake for the the first time)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_COMPILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_COMPILE_FLAGS}")
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

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n==================|  BinPAC Build Summary  |===================="
    "\n"
    "\nInstall prefix:    ${binpac_install_summary}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nRelease mode:      ${ENABLE_RELEASE}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\n================================================================\n"
)
