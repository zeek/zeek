project(Bro C CXX)

# When changing the minimum version here, also adapt
# aux/bro-aux/plugin-support/skeleton/CMakeLists.txt
cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

include(cmake/CommonCMakeConfig.cmake)

########################################################################
## Project/Build Configuration

if ( ENABLE_CCACHE )
    find_program(CCACHE_PROGRAM ccache)

    if ( NOT CCACHE_PROGRAM )
        message(FATAL_ERROR "ccache not found")
    endif ()

    message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   ${CCACHE_PROGRAM})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
endif ()

set(BRO_ROOT_DIR ${CMAKE_INSTALL_PREFIX})
if (NOT BRO_SCRIPT_INSTALL_PATH)
    # set the default Bro script installation path (user did not specify one)
    set(BRO_SCRIPT_INSTALL_PATH ${BRO_ROOT_DIR}/share/bro)
endif ()

if (NOT BRO_MAN_INSTALL_PATH)
    # set the default Bro man page installation path (user did not specify one)
    set(BRO_MAN_INSTALL_PATH ${BRO_ROOT_DIR}/share/man)
endif ()

# sanitize the Bro script install directory into an absolute path
# (CMake is confused by ~ as a representation of home directory)
get_filename_component(BRO_SCRIPT_INSTALL_PATH ${BRO_SCRIPT_INSTALL_PATH}
    ABSOLUTE)

set(BRO_PLUGIN_INSTALL_PATH ${BRO_ROOT_DIR}/lib/bro/plugins CACHE STRING "Installation path for plugins" FORCE)

configure_file(zeek-path-dev.in ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.sh
     "export BROPATH=`${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev`\n"
     "export BRO_PLUGIN_PATH=\"${CMAKE_CURRENT_BINARY_DIR}/src\":${BRO_PLUGIN_PATH}\n"
     "export PATH=\"${CMAKE_CURRENT_BINARY_DIR}/src\":$PATH\n")

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.csh
     "setenv BROPATH `${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev`\n"
     "setenv BRO_PLUGIN_PATH \"${CMAKE_CURRENT_BINARY_DIR}/src\":${BRO_PLUGIN_PATH}\n"
     "setenv PATH \"${CMAKE_CURRENT_BINARY_DIR}/src\":$PATH\n")

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)
execute_process(COMMAND grep "^#define  *BRO_PLUGIN_API_VERSION"
                INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/plugin/Plugin.h
                OUTPUT_VARIABLE API_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX REPLACE "^#define.*VERSION *" "" API_VERSION "${API_VERSION}")

string(REPLACE "." " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
set(VERSION_MAJ_MIN "${VERSION_MAJOR}.${VERSION_MINOR}")

set(VERSION_C_IDENT "${VERSION}_plugin_${API_VERSION}")
string(REGEX REPLACE "-[0-9]*$" "_git" VERSION_C_IDENT "${VERSION_C_IDENT}")
string(REGEX REPLACE "[^a-zA-Z0-9_\$]" "_" VERSION_C_IDENT "${VERSION_C_IDENT}")

if(${ENABLE_DEBUG})
    set(VERSION_C_IDENT "${VERSION_C_IDENT}_debug")
endif()

########################################################################
## Dependency Configuration

include(FindRequiredPackage)

# Check cache value first to avoid displaying "Found sed" messages everytime
if (NOT SED_EXE)
    find_program(SED_EXE sed)
    if (NOT SED_EXE)
        message(FATAL_ERROR "Could not find required dependency: sed")
    else ()
        message(STATUS "Found sed: ${SED_EXE}")
    endif ()
endif ()

FindRequiredPackage(PythonInterp)
FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)
FindRequiredPackage(PCAP)
FindRequiredPackage(OpenSSL)
FindRequiredPackage(BIND)
FindRequiredPackage(ZLIB)

if (NOT BINPAC_EXE_PATH AND
    EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/aux/binpac/CMakeLists.txt)

    set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})

    if ( BUILD_STATIC_BINPAC )
      set(ENABLE_STATIC_ONLY true)
    endif()

    add_subdirectory(aux/binpac)
    set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})
endif ()
FindRequiredPackage(BinPAC)

if ( NOT BIFCL_EXE_PATH )
  add_subdirectory(aux/bifcl)
endif ()

if (ENABLE_JEMALLOC)
    find_package(JeMalloc)
endif ()

if ( BISON_VERSION AND BISON_VERSION VERSION_LESS 2.5 )
    set(MISSING_PREREQS true)
    list(APPEND MISSING_PREREQ_DESCS
         " Could not find prerequisite package Bison >= 2.5, found: ${BISON_VERSION}")
endif ()

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR}
                    ${BinPAC_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIR}
                    ${JEMALLOC_INCLUDE_DIR}
)

# Optional Dependencies

set(USE_GEOIP false)
find_package(LibMMDB)
if (LIBMMDB_FOUND)
    set(USE_GEOIP true)
    include_directories(BEFORE ${LibMMDB_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibMMDB_LIBRARY})
endif ()

set(USE_KRB5 false)
if ( ${CMAKE_SYSTEM_NAME} MATCHES Linux )
  find_package(LibKrb5)
  if (LIBKRB5_FOUND)
     set(USE_KRB5 true)
     include_directories(BEFORE ${LibKrb5_INCLUDE_DIR})
     list(APPEND OPTLIBS ${LibKrb5_LIBRARY})
  endif ()
endif ()

set(HAVE_PERFTOOLS false)
set(USE_PERFTOOLS_DEBUG false)
set(USE_PERFTOOLS_TCMALLOC false)

if (NOT DISABLE_PERFTOOLS)
   find_package(GooglePerftools)
endif ()

if (GOOGLEPERFTOOLS_FOUND OR TCMALLOC_FOUND)
    set(HAVE_PERFTOOLS true)
    # Non-Linux systems may not be well-supported by gperftools, so
    # require explicit request from user to enable it in that case.
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ENABLE_PERFTOOLS)
        set(USE_PERFTOOLS_TCMALLOC true)

        if (ENABLE_PERFTOOLS_DEBUG)
            # Enable heap debugging with perftools.
            set(USE_PERFTOOLS_DEBUG true)
            include_directories(BEFORE ${GooglePerftools_INCLUDE_DIR})
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES_DEBUG})
        else ()
            # Link in tcmalloc for better performance.
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
        endif ()
    endif ()
endif ()

if (ENABLE_PERFTOOLS_DEBUG OR ENABLE_PERFTOOLS)
    # Just a no op to prevent CMake from complaining about manually-specified
    # ENABLE_PERFTOOLS_DEBUG or ENABLE_PERFTOOLS not being used if google
    # perftools weren't found
endif ()

# Making sure any non-standard OpenSSL includes get searched earlier
# than other dependencies which tend to be in standard system locations
# and thus cause the system OpenSSL headers to still be picked up even
# if one specifies --with-openssl (which may be common).
include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})

# Alpine support
if ( ${CMAKE_SYSTEM_NAME} MATCHES Linux AND EXISTS /etc/os-release )
    execute_process(
        COMMAND grep -q alpine /etc/os-release
        RESULT_VARIABLE os_release_alpine
    )

    if ( os_release_alpine EQUAL 0 )
        find_package(FTS REQUIRED)
        list(APPEND OPTLIBS ${FTS_LIBRARY})
        include_directories(BEFORE ${FTS_INCLUDE_DIR})
    endif ()
endif ()

set(brodeps
    ${BinPAC_LIBRARY}
    ${PCAP_LIBRARY}
    ${OPENSSL_LIBRARIES}
    ${BIND_LIBRARY}
    ${ZLIB_LIBRARY}
    ${JEMALLOC_LIBRARIES}
    ${OPTLIBS}
)

########################################################################
## System Introspection

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)
include(CheckSymbolExists)
check_symbol_exists(htonll arpa/inet.h HAVE_BYTEORDER_64)

include(OSSpecific)
include(CheckTypes)
include(CheckHeaders)
include(CheckFunctions)
include(MiscTests)
include(PCAPTests)
include(OpenSSLTests)
include(CheckNameserCompat)
include(GetArchitecture)
include(RequireCXX11)

if ( (OPENSSL_VERSION VERSION_EQUAL "1.1.0") OR (OPENSSL_VERSION VERSION_GREATER "1.1.0") )
  set(BRO_HAVE_OPENSSL_1_1 true CACHE INTERNAL "" FORCE)
endif()

# Tell the plugin code that we're building as part of the main tree.
set(BRO_PLUGIN_INTERNAL_BUILD true CACHE INTERNAL "" FORCE)

set(DEFAULT_BROPATH .:${BRO_SCRIPT_INSTALL_PATH}:${BRO_SCRIPT_INSTALL_PATH}/policy:${BRO_SCRIPT_INSTALL_PATH}/site)

if ( NOT BINARY_PACKAGING_MODE )
    set(BRO_DIST ${CMAKE_SOURCE_DIR})
endif ()

string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h DESTINATION include/bro)

if ( CAF_ROOT_DIR )
  set(ZEEK_CONFIG_CAF_ROOT_DIR ${CAF_ROOT_DIR})
else ()
  set(ZEEK_CONFIG_CAF_ROOT_DIR ${BRO_ROOT_DIR})
endif ()

if ( BinPAC_ROOT_DIR )
  set(ZEEK_CONFIG_BINPAC_ROOT_DIR ${BinPAC_ROOT_DIR})
else ()
  set(ZEEK_CONFIG_BINPAC_ROOT_DIR ${BRO_ROOT_DIR})
endif ()

if ( BROKER_ROOT_DIR )
  set(ZEEK_CONFIG_BROKER_ROOT_DIR ${BROKER_ROOT_DIR})
else ()
  set(ZEEK_CONFIG_BROKER_ROOT_DIR ${BRO_ROOT_DIR})
endif ()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config @ONLY)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/zeek-config DESTINATION bin)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cmake DESTINATION share/bro
        USE_SOURCE_PERMISSIONS)

# Install wrapper script for Bro-to-Zeek renaming.
include(InstallShellScript)
include(InstallSymlink)
InstallShellScript("bin" "zeek-wrapper.in" "zeek-wrapper")
InstallSymlink("${CMAKE_INSTALL_PREFIX}/bin/zeek-wrapper" "${CMAKE_INSTALL_PREFIX}/bin/bro-config")
InstallSymlink("${CMAKE_INSTALL_PREFIX}/include/bro/zeek-config.h" "${CMAKE_INSTALL_PREFIX}/include/bro/bro-config.h")

########################################################################
## Recurse on sub-directories

if ( BROKER_ROOT_DIR )
  find_package(Broker REQUIRED)
  find_package(CAF COMPONENTS core io openssl REQUIRED)

  set(brodeps ${brodeps} ${BROKER_LIBRARY} ${CAF_LIBRARIES})
  include_directories(BEFORE ${BROKER_INCLUDE_DIR})
else ()
  set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})

  if ( BUILD_STATIC_BROKER )
    set(ENABLE_STATIC_ONLY true)
  endif()

  add_subdirectory(aux/broker)
  set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})

  if ( BUILD_STATIC_BROKER )
    set(brodeps ${brodeps} broker_static)
  else()
    set(brodeps ${brodeps} broker)
  endif()
  include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/aux/broker
                             ${CMAKE_CURRENT_BINARY_DIR}/aux/broker)
endif ()

# CAF headers aren't necessarily in same location as Broker headers and
# inclusion of a Broker header may pull in CAF headers.
include_directories(BEFORE ${CAF_INCLUDE_DIR_CORE})
include_directories(BEFORE ${CAF_INCLUDE_DIR_IO})
include_directories(BEFORE ${CAF_INCLUDE_DIR_OPENSSL})

add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(man)

include(CheckOptionalBuildSources)

CheckOptionalBuildSources(aux/broctl   Broctl   INSTALL_BROCTL)
CheckOptionalBuildSources(aux/bro-aux  Bro-Aux  INSTALL_AUX_TOOLS)
CheckOptionalBuildSources(aux/broccoli Broccoli INSTALL_BROCCOLI)

########################################################################
## Packaging Setup

if (INSTALL_BROCTL)
    # CPack RPM Generator may not automatically detect this
    set(CPACK_RPM_PACKAGE_REQUIRES "python >= 2.6.0")
endif ()

# If this CMake project is a sub-project of another, we will not
# configure the generic packaging because CPack will fail in the case
# that the parent project has already configured packaging
if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()

########################################################################
## Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n====================|  Bro Build Summary  |====================="
    "\n"
    "\nBuild type:        ${CMAKE_BUILD_TYPE}"
    "\nBuild dir:         ${CMAKE_BINARY_DIR}"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nBro Script Path:   ${BRO_SCRIPT_INSTALL_PATH}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nBroccoli:          ${INSTALL_BROCCOLI}"
    "\nBroctl:            ${INSTALL_BROCTL}"
    "\nAux. Tools:        ${INSTALL_AUX_TOOLS}"
    "\n"
    "\nlibmaxminddb:      ${USE_GEOIP}"
    "\nKerberos:          ${USE_KRB5}"
    "\ngperftools found:  ${HAVE_PERFTOOLS}"
    "\n        tcmalloc:  ${USE_PERFTOOLS_TCMALLOC}"
    "\n       debugging:  ${USE_PERFTOOLS_DEBUG}"
    "\njemalloc:          ${ENABLE_JEMALLOC}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
