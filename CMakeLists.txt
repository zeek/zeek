# When changing the minimum version here, also adapt
# aux/zeek-aux/plugin-support/skeleton/CMakeLists.txt
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(Zeek C CXX)

if ( NOT CMAKE_INSTALL_LIBDIR )
    # Currently, some sub-projects may use GNUInstallDirs.cmake to choose the
    # library install dir, while others just default to "lib".  For sake of
    # consistency, this just overrides the former to always use "lib" in case
    # it would have chosen something else, like "lib64", but a thing for the
    # future may be to standardize all sub-projects to use GNUInstallDirs.
    set(CMAKE_INSTALL_LIBDIR lib)
endif ()

include(cmake/CommonCMakeConfig.cmake)
include(cmake/FindClangTidy.cmake)

########################################################################
## Project/Build Configuration


if (ENABLE_ZEEK_UNIT_TESTS)
    enable_testing()
    add_definitions(-DDOCTEST_CONFIG_SUPER_FAST_ASSERTS)
else ()
    add_definitions(-DDOCTEST_CONFIG_DISABLE)
endif ()

if ( ENABLE_CCACHE )
    find_program(CCACHE_PROGRAM ccache)

    if ( NOT CCACHE_PROGRAM )
        message(FATAL_ERROR "ccache not found")
    endif ()

    message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   ${CCACHE_PROGRAM})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
endif ()

set(ZEEK_ROOT_DIR ${CMAKE_INSTALL_PREFIX})
if (NOT ZEEK_SCRIPT_INSTALL_PATH)
    # set the default Zeek script installation path (user did not specify one)
    set(ZEEK_SCRIPT_INSTALL_PATH ${ZEEK_ROOT_DIR}/share/zeek)
endif ()

if (NOT ZEEK_MAN_INSTALL_PATH)
    # set the default Zeek man page installation path (user did not specify one)
    set(ZEEK_MAN_INSTALL_PATH ${ZEEK_ROOT_DIR}/share/man)
endif ()

# sanitize the Zeek script install directory into an absolute path
# (CMake is confused by ~ as a representation of home directory)
get_filename_component(ZEEK_SCRIPT_INSTALL_PATH ${ZEEK_SCRIPT_INSTALL_PATH}
    ABSOLUTE)

set(BRO_PLUGIN_INSTALL_PATH ${ZEEK_ROOT_DIR}/lib/zeek/plugins CACHE STRING "Installation path for plugins" FORCE)

configure_file(zeek-path-dev.in ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev)
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                "${CMAKE_CURRENT_BINARY_DIR}/zeek-wrapper.in"
                "${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev")

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.sh
     "export ZEEKPATH=`${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev`\n"
     "export ZEEK_PLUGIN_PATH=\"${CMAKE_CURRENT_BINARY_DIR}/src\":${ZEEK_PLUGIN_PATH}\n"
     "export PATH=\"${CMAKE_CURRENT_BINARY_DIR}/src\":$PATH\n")

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.csh
     "setenv ZEEKPATH `${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev`\n"
     "setenv ZEEK_PLUGIN_PATH \"${CMAKE_CURRENT_BINARY_DIR}/src\":${ZEEK_PLUGIN_PATH}\n"
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

if ( NOT BINARY_PACKAGING_MODE )
    macro(_make_install_dir_symlink _target _link)
      install(CODE "
        if ( \"\$ENV{DESTDIR}\" STREQUAL \"\" )
          if ( EXISTS \"${_target}\" AND NOT EXISTS \"${_link}\" )
            message(STATUS \"WARNING: installed ${_link} as symlink to ${_target}\")
            execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
              \"${_target}\" \"${_link}\")
          endif ()
        endif ()
      ")
    endmacro()

    if ( "${CMAKE_INSTALL_PREFIX}" STREQUAL "/usr/local/zeek" )
        # If we're installing into the default prefix, check if the
        # old default prefix already exists and symlink to it.
        # This is done to help keep custom user configuration/installation
        # if they're upgrading from a version before Zeek 3.0.
        _make_install_dir_symlink("/usr/local/bro" "/usr/local/zeek")
    endif ()

    # Check whether we need to symlink directories used by versions
    # before Zeek 3.0.
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/include/bro" "${CMAKE_INSTALL_PREFIX}/include/zeek")
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/share/bro" "${CMAKE_INSTALL_PREFIX}/share/zeek")
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/lib/bro" "${CMAKE_INSTALL_PREFIX}/lib/zeek")
endif ()

if ( ZEEK_SANITIZERS )
    # Check the thread library info early as setting compiler flags seems to
    # interfere with the detection and cause CMAKE_THREAD_LIBS_INIT to not
    # include -lpthread when it should.
    find_package(Threads)
    set(_sanitizer_flags "-fsanitize=${ZEEK_SANITIZERS}")
    set(_sanitizer_flags "${_sanitizer_flags} -fno-omit-frame-pointer")
    set(_sanitizer_flags "${_sanitizer_flags} -fno-optimize-sibling-calls")

    if ( NOT DEFINED ENV{NO_OPTIMIZATIONS} )
      # Using -O1 is generally the suggestion to get more reasonable
      # performance.  The one downside is it that the compiler may optimize out
      # code that otherwise generates an error/leak in a -O0 build, but that
      # should be rare and users mostly will not be running unoptimized builds
      # in production anyway.
      set(_sanitizer_flags "${_sanitizer_flags} -O1")
    endif ()

    # Technically, the we also need to use the compiler to drive linking and
    # give the sanitizer flags there, too.  However, CMake, by default, uses
    # the compiler for linking and so the automatically flags get used.  See
    # https://cmake.org/pipermail/cmake/2014-August/058268.html
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_sanitizer_flags}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_sanitizer_flags}")
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

    if (NOT JEMALLOC_FOUND)
        message(FATAL_ERROR "Could not find requested JeMalloc")
    endif()
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

if ( CAF_ROOT_DIR )
  find_package(CAF COMPONENTS core io openssl REQUIRED)
endif ()

add_subdirectory(aux/paraglob)
set(zeekdeps ${zeekdeps} paraglob)

if ( BROKER_ROOT_DIR )
  # Avoid calling find_package(CAF) twice.
  if ( NOT CAF_ROOT_DIR )
    find_package(CAF COMPONENTS core io openssl REQUIRED)
  endif ()
  find_package(Broker REQUIRED)
  set(zeekdeps ${zeekdeps} ${BROKER_LIBRARY})
  set(broker_includes ${BROKER_INCLUDE_DIR})
else ()
  if ( ZEEK_SANITIZERS )
    set(BROKER_SANITIZERS ${ZEEK_SANITIZERS})
  endif ()

  set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})

  if ( BUILD_STATIC_BROKER )
    set(ENABLE_STATIC_ONLY true)
  endif()

  add_subdirectory(aux/broker)
  set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})

  if ( BUILD_STATIC_BROKER )
    set(zeekdeps ${zeekdeps} broker_static)
  else()
    set(zeekdeps ${zeekdeps} broker)
  endif()
  set(broker_includes ${CMAKE_CURRENT_SOURCE_DIR}/aux/broker/include ${CMAKE_CURRENT_BINARY_DIR}/aux/broker/include)
endif ()

# CAF_LIBRARIES and CAF_INCLUDE_DIRS are defined either by calling
# find_package(CAF) or by calling add_subdirectory(aux/broker). In either case,
# we have to care about CAF here because Broker headers can pull in CAF
# headers.
set(zeekdeps ${zeekdeps} ${CAF_LIBRARIES})
include_directories(BEFORE ${broker_includes} ${CAF_INCLUDE_DIRS})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/aux/paraglob/include)
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

if ( ENABLE_PERFTOOLS )
   find_package(GooglePerftools)

    if ( GOOGLEPERFTOOLS_FOUND OR TCMALLOC_FOUND )
        set(HAVE_PERFTOOLS true)
        set(USE_PERFTOOLS_TCMALLOC true)

        if (ENABLE_PERFTOOLS_DEBUG)
            # Enable heap debugging with perftools.
            set(USE_PERFTOOLS_DEBUG true)
            include_directories(BEFORE ${GooglePerftools_INCLUDE_DIR})
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES_DEBUG})
        else ()
            # Link in tcmalloc.
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
        endif ()
    else()
        message(FATAL_ERROR "Could not find requested Google Perftools.")
    endif ()
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

set(zeekdeps ${zeekdeps}
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
include(RequireCXX17)

if ( (OPENSSL_VERSION VERSION_EQUAL "1.1.0") OR (OPENSSL_VERSION VERSION_GREATER "1.1.0") )
  set(ZEEK_HAVE_OPENSSL_1_1 true CACHE INTERNAL "" FORCE)
endif()

# Tell the plugin code that we're building as part of the main tree.
set(ZEEK_PLUGIN_INTERNAL_BUILD true CACHE INTERNAL "" FORCE)

set(DEFAULT_ZEEKPATH .:${ZEEK_SCRIPT_INSTALL_PATH}:${ZEEK_SCRIPT_INSTALL_PATH}/policy:${ZEEK_SCRIPT_INSTALL_PATH}/site)

if ( NOT BINARY_PACKAGING_MODE )
    set(ZEEK_DIST ${CMAKE_SOURCE_DIR})
endif ()

string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bro-config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/bro-config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h DESTINATION include/zeek)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bro-config.h DESTINATION include/zeek)

if ( CAF_ROOT_DIR )
  set(ZEEK_CONFIG_CAF_ROOT_DIR ${CAF_ROOT_DIR})
else ()
  set(ZEEK_CONFIG_CAF_ROOT_DIR ${ZEEK_ROOT_DIR})
endif ()

if ( BinPAC_ROOT_DIR )
  set(ZEEK_CONFIG_BINPAC_ROOT_DIR ${BinPAC_ROOT_DIR})
else ()
  set(ZEEK_CONFIG_BINPAC_ROOT_DIR ${ZEEK_ROOT_DIR})
endif ()

if ( BROKER_ROOT_DIR )
  set(ZEEK_CONFIG_BROKER_ROOT_DIR ${BROKER_ROOT_DIR})
else ()
  set(ZEEK_CONFIG_BROKER_ROOT_DIR ${ZEEK_ROOT_DIR})
endif ()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config @ONLY)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/zeek-config DESTINATION bin)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cmake DESTINATION share/zeek
        USE_SOURCE_PERMISSIONS)

# Install wrapper script for Bro-to-Zeek renaming.
include(InstallShellScript)
include(InstallSymlink)
InstallShellScript("bin" "zeek-wrapper.in" "zeek-wrapper")
InstallSymlink("${CMAKE_INSTALL_PREFIX}/bin/zeek-wrapper" "${CMAKE_INSTALL_PREFIX}/bin/bro-config")

########################################################################
## Recurse on sub-directories

add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(man)

include(CheckOptionalBuildSources)

CheckOptionalBuildSources(aux/zeekctl   ZeekControl INSTALL_ZEEKCTL)
CheckOptionalBuildSources(aux/zeek-aux  Zeek-Aux  INSTALL_AUX_TOOLS)

########################################################################
## Packaging Setup

if (INSTALL_ZEEKCTL)
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
    "\n====================|  Zeek Build Summary  |===================="
    "\n"
    "\nBuild type:        ${CMAKE_BUILD_TYPE}"
    "\nBuild dir:         ${CMAKE_BINARY_DIR}"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nZeek Script Path:  ${ZEEK_SCRIPT_INSTALL_PATH}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nUnit tests:        ${ENABLE_ZEEK_UNIT_TESTS}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nZeekControl:       ${INSTALL_ZEEKCTL}"
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
