cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# ##############################################################################
# Dependency Configuration

find_package(PCAP REQUIRED)

include_directories(BEFORE ${PCAP_INCLUDE_DIR})

# ##############################################################################
# System Introspection

include(CheckHeaders)
include(CheckFunctions)
include(CheckNameserCompat)
include(MiscTests)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

# ##############################################################################
# Recurse on sub-directories

# For binary packaging or if this is the main CMake project, go through the
# regular install target, else use a custom target so programs have to be
# explicitly installed by the user via "make install-aux"
macro (AddAuxInstallTarget _target)
    add_custom_target(
            install-${_target} COMMAND ${CMAKE_COMMAND} -E make_directory
        ${CMAKE_INSTALL_PREFIX}/bin
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${_target}> ${CMAKE_INSTALL_PREFIX}/bin)
    add_dependencies(install-${_target} ${_target})
    set(AUX_TARGETS install-${_target};${AUX_TARGETS})
    set(AUX_TARGETS ${AUX_TARGETS} PARENT_SCOPE)
endmacro (AddAuxInstallTarget)

if (NOT ZEEK_MAN_INSTALL_PATH)
    set(ZEEK_MAN_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/share/man)
endif ()

add_subdirectory(adtrace)
add_subdirectory(zeek-archiver)
add_subdirectory(zeek-cut)
add_subdirectory(rst)

add_custom_target(install-aux
    COMMENT "Zeek auxiliary tools installed to ${CMAKE_INSTALL_PREFIX}/bin")
add_dependencies(install-aux ${AUX_TARGETS})
