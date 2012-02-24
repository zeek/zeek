project(BinPAC C CXX)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)
include(cmake/CommonCMakeConfig.cmake)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" BINPAC_VERSION LIMIT_COUNT 1)

########################################################################
## Dependency Configuration

include(FindRequiredPackage)

FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

########################################################################
## System Introspection

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

########################################################################
## Recurse on sub-directories

add_subdirectory(lib)
add_subdirectory(src)

########################################################################
## Build Summary

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
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
