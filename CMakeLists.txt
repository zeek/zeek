# When changing the minimum version here, also adapt
# auxil/zeek-aux/plugin-support/skeleton/CMakeLists.txt
cmake_minimum_required(VERSION 3.5...3.18 FATAL_ERROR)

project(Zeek C CXX)

include(GNUInstallDirs)

include(cmake/CommonCMakeConfig.cmake)
include(cmake/FindClangTidy.cmake)
include(cmake/CheckCompilerArch.cmake)

########################################################################
## Project/Build Configuration

if ( ZEEK_ENABLE_FUZZERS )
    # Fuzzers use shared lib to save disk space, so need -fPIC on everything
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif ()

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

# A folder for library-like Zeek-specific things: Python modules, Zeek
# plugins, etc.
set(ZEEK_LIBDIR_PATH ${CMAKE_INSTALL_FULL_LIBDIR}/zeek)

if (ZEEK_PLUGIN_DIR)
    set(BRO_PLUGIN_INSTALL_PATH ${ZEEK_PLUGIN_DIR}
        CACHE STRING "Installation path for plugins" FORCE)
else ()
    set(BRO_PLUGIN_INSTALL_PATH ${ZEEK_LIBDIR_PATH}/plugins
        CACHE STRING "Installation path for plugins" FORCE)
endif ()

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

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)
set(VERSION_MAJ_MIN "${VERSION_MAJOR}.${VERSION_MINOR}")
math(EXPR ZEEK_VERSION_NUMBER
     "${VERSION_MAJOR} * 10000 + ${VERSION_MINOR} * 100 + ${VERSION_PATCH}")

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
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/lib/bro" "${CMAKE_INSTALL_FULL_LIBDIR}/zeek")
endif ()

if ( ZEEK_SANITIZERS )
    # Check the thread library info early as setting compiler flags seems to
    # interfere with the detection and cause CMAKE_THREAD_LIBS_INIT to not
    # include -lpthread when it should.
    find_package(Threads)

    string(REPLACE "," " " _sanitizer_args "${ZEEK_SANITIZERS}")
    separate_arguments(_sanitizer_args)
    set(ZEEK_SANITIZERS "")

    foreach ( _sanitizer ${_sanitizer_args} )
        if ( ZEEK_SANITIZERS )
            set(ZEEK_SANITIZERS "${ZEEK_SANITIZERS},")
        endif ()

        if ( _sanitizer STREQUAL "thread" )
            set(ZEEK_TSAN true)
        endif ()

        if ( NOT _sanitizer STREQUAL "undefined" )
            set(ZEEK_SANITIZERS "${ZEEK_SANITIZERS}${_sanitizer}")
            continue()
        endif ()

        if ( NOT DEFINED ZEEK_SANITIZER_UB_CHECKS )
            if ( DEFINED ENV{ZEEK_TAILORED_UB_CHECKS} )
                # list(APPEND _check_list "alignment") # TODO: fix associated errors
                list(APPEND _check_list "bool")
                # list(APPEND _check_list "builtin") # Not implemented in older GCCs
                list(APPEND _check_list "bounds") # Covers both array/local bounds options below
                # list(APPEND _check_list "array-bounds") # Not implemented by GCC
                # list(APPEND _check_list "local-bounds") # Not normally part of "undefined"
                list(APPEND _check_list "enum")
                list(APPEND _check_list "float-cast-overflow")
                list(APPEND _check_list "float-divide-by-zero")
                # list(APPEND _check_list "function") # Not implemented by GCC
                # list(APPEND _check_list "implicit-unsigned-integer-truncation") # Not truly UB
                # list(APPEND _check_list "implicit-signed-integer-truncation") # Not truly UB
                # list(APPEND _check_list "implicit-integer-sign-change") # Not truly UB
                list(APPEND _check_list "integer-divide-by-zero")
                list(APPEND _check_list "nonnull-attribute")
                # list(APPEND _check_list "null") # TODO: fix associated errors
                # list(APPEND _check_list "nullability-arg") # Not normally part of "undefined"
                # list(APPEND _check_list "nullability-assign") # Not normally part of "undefined"
                # list(APPEND _check_list "nullability-return") # Not normally part of "undefined"
                # list(APPEND _check_list "objc-cast") # Not truly UB
                list(APPEND _check_list "object-size")
                # list(APPEND _check_list "pointer-overflow") # Not implemented in older GCCs
                list(APPEND _check_list "return")
                list(APPEND _check_list "returns-nonnull-attribute")
                list(APPEND _check_list "shift")
                # list(APPEND _check_list "unsigned-shift-base") # Not implemented by GCC
                list(APPEND _check_list "signed-integer-overflow")
                list(APPEND _check_list "unreachable")
                # list(APPEND _check_list "unsigned-integer-overflow") # Not truly UB
                list(APPEND _check_list "vla-bound")
                # list(APPEND _check_list "vptr") # TODO: fix associated errors

                string(REPLACE ";" "," _ub_checks "${_check_list}")
                set(ZEEK_SANITIZER_UB_CHECKS "${_ub_checks}" CACHE INTERNAL "" FORCE)
            else ()
                set(ZEEK_SANITIZER_UB_CHECKS "undefined" CACHE INTERNAL "" FORCE)
            endif ()
        endif ()

        set(ZEEK_SANITIZERS "${ZEEK_SANITIZERS}${ZEEK_SANITIZER_UB_CHECKS}")
    endforeach ()

    set(_sanitizer_flags "-fsanitize=${ZEEK_SANITIZERS}")

    if ( ZEEK_SANITIZER_UB_CHECKS )
        set(_sanitizer_flags "${_sanitizer_flags} -fno-sanitize-recover=${ZEEK_SANITIZER_UB_CHECKS}")
    endif ()

    set(_sanitizer_flags "${_sanitizer_flags} -fno-omit-frame-pointer")
    set(_sanitizer_flags "${_sanitizer_flags} -fno-optimize-sibling-calls")

    if ( NOT DEFINED ZEEK_SANITIZER_OPTIMIZATIONS )
        if ( DEFINED ENV{NO_OPTIMIZATIONS} )
            # Using -O1 is generally the suggestion to get more reasonable
            # performance.  The one downside is it that the compiler may
            # optimize out code that otherwise generates an error/leak in a -O0
            # build, but that should be rare and users mostly will not be
            # running unoptimized builds in production anyway.
            set(ZEEK_SANITIZER_OPTIMIZATIONS false CACHE INTERNAL "" FORCE)
        else ()
            set(ZEEK_SANITIZER_OPTIMIZATIONS true CACHE INTERNAL "" FORCE)
        endif ()
    endif ()

    if ( ZEEK_SANITIZER_OPTIMIZATIONS )
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

list(APPEND Python_ADDITIONAL_VERSIONS 3)
FindRequiredPackage(PythonInterp)
FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)
FindRequiredPackage(PCAP)
FindRequiredPackage(OpenSSL)
FindRequiredPackage(BIND)
FindRequiredPackage(ZLIB)

# Installation directory for the distribution's Python modules. An
# override via configure's --python-dir wins, specifying a directory
# explicitly. Next is --python-prefix, which includes a versioned
# Python folder as the --prefix option in distutils does. Next
# consider a distutils --home style override via --python-home, and
# finally default to "zeek/python" in our libdir.
if (ZEEK_PYTHON_DIR)
    set(py_mod_install_dir ${ZEEK_PYTHON_DIR})
elseif (ZEEK_PYTHON_PREFIX)
    set(pyver ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR})
    set(py_mod_install_dir ${ZEEK_PYTHON_PREFIX}/lib/python${pyver}/site-packages)
elseif (ZEEK_PYTHON_HOME)
    set(py_mod_install_dir ${ZEEK_PYTHON_HOME}/lib/python)
else ()
    set(py_mod_install_dir ${ZEEK_LIBDIR_PATH}/python)
endif ()
set(PY_MOD_INSTALL_DIR ${py_mod_install_dir}
    CACHE STRING "Installation path for Python modules" FORCE)

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/auxil/binpac/CMakeLists.txt)

    set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})

    if ( BUILD_STATIC_BINPAC )
      set(ENABLE_STATIC_ONLY true)
    endif()

    add_subdirectory(auxil/binpac)
    set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})
endif ()
FindRequiredPackage(BinPAC)

if ( NOT BIFCL_EXE_PATH )
  add_subdirectory(auxil/bifcl)
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

set(ZEEK_PYTHON_MIN 3.5.0)

if ( PYTHON_VERSION_STRING VERSION_LESS ${ZEEK_PYTHON_MIN} )
    message(FATAL_ERROR "Python ${ZEEK_PYTHON_MIN} or greater is required.")
endif ()

if ( CAF_ROOT OR BROKER_ROOT_DIR )
  # TODO: drop < 3.12 compatibility check when raising the minimum CMake version
  if ( CAF_ROOT AND CMAKE_VERSION VERSION_LESS 3.12 )
    find_package(CAF ${CAF_VERSION_MIN_REQUIRED} REQUIRED
                 COMPONENTS openssl test io core
                 PATHS "${CAF_ROOT}")
  else ()
    find_package(CAF ${CAF_VERSION_MIN_REQUIRED} REQUIRED
                 COMPONENTS openssl test io core)
  endif ()
  message(STATUS "Using system CAF version ${CAF_VERSION}")
  # TODO: drop these legacy variables and simply use the targets consistently
  set(CAF_LIBRARIES CAF::core CAF::io CAF::openssl CACHE INTERNAL "")
  set(caf_dirs "")
  foreach (caf_lib IN LISTS CAF_LIBRARIES ITEMS CAF::test)
    get_target_property(dirs ${caf_lib} INTERFACE_INCLUDE_DIRECTORIES)
    if ( dirs )
      list(APPEND caf_dirs ${dirs})
    endif ()
  endforeach ()
  list(REMOVE_DUPLICATES caf_dirs)
  list(GET caf_dirs 0 caf_dir)
  set(CAF_INCLUDE_DIRS "${caf_dirs}" CACHE INTERNAL "")
endif ()

add_subdirectory(auxil/paraglob)
set(zeekdeps ${zeekdeps} paraglob)

if ( BROKER_ROOT_DIR )
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

  add_subdirectory(auxil/broker)
  set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})

  if ( BUILD_STATIC_BROKER )
    set(zeekdeps ${zeekdeps} broker_static)
  else()
    set(zeekdeps ${zeekdeps} broker)
  endif()
  set(broker_includes ${CMAKE_CURRENT_SOURCE_DIR}/auxil/broker/include ${CMAKE_CURRENT_BINARY_DIR}/auxil/broker/include)
endif ()

# CAF_LIBRARIES and CAF_INCLUDE_DIRS are defined either by calling
# find_package(CAF) or by calling add_subdirectory(auxil/broker). In either case,
# we have to care about CAF here because Broker headers can pull in CAF
# headers.
set(zeekdeps ${zeekdeps} ${CAF_LIBRARIES})
include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR}
                    ${BinPAC_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIR}
                    ${JEMALLOC_INCLUDE_DIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/auxil/rapidjson/include/rapidjson
        DESTINATION include/zeek/3rdparty/rapidjson/include)

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

# Determine if libfts is external to libc, i.e. musl
find_package(FTS)
if ( FTS_FOUND )
    list(APPEND OPTLIBS ${FTS_LIBRARY})
    include_directories(BEFORE ${FTS_INCLUDE_DIR})
endif ()

# Any headers that are possibly bundled in the Zeek source-tree and that are supposed
# to have priority over any pre-existing/system-wide headers need to appear early in
# compiler search path.
include_directories(BEFORE ${broker_includes} ${CAF_INCLUDE_DIRS})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/auxil/highwayhash)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/auxil/paraglob/include)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/auxil/rapidjson/include)

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
include(FindKqueue)

if ( (OPENSSL_VERSION VERSION_EQUAL "1.1.0") OR (OPENSSL_VERSION VERSION_GREATER "1.1.0") )
  set(ZEEK_HAVE_OPENSSL_1_1 true CACHE INTERNAL "" FORCE)
endif()

# Tell the plugin code that we're building as part of the main tree.
set(ZEEK_PLUGIN_INTERNAL_BUILD true CACHE INTERNAL "" FORCE)

set(DEFAULT_ZEEKPATH .:${ZEEK_SCRIPT_INSTALL_PATH}:${ZEEK_SCRIPT_INSTALL_PATH}/policy:${ZEEK_SCRIPT_INSTALL_PATH}/site:${ZEEK_SCRIPT_INSTALL_PATH}/builtin-plugins)

if ( NOT BINARY_PACKAGING_MODE )
    set(ZEEK_DIST ${PROJECT_SOURCE_DIR})
endif ()

string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h DESTINATION include/zeek)
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                "."
                "${CMAKE_CURRENT_BINARY_DIR}/zeek")

if ( CAF_ROOT )
  set(ZEEK_CONFIG_CAF_ROOT_DIR ${CAF_ROOT})
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

if ( PCAP_INCLUDE_DIR )
    set(ZEEK_CONFIG_PCAP_INCLUDE_DIR ${PCAP_INCLUDE_DIR})
endif ()
if ( ZLIB_INCLUDE_DIR )
    set(ZEEK_CONFIG_ZLIB_INCLUDE_DIR ${ZLIB_INCLUDE_DIR})
endif ()
if ( OPENSSL_INCLUDE_DIR )
    set(ZEEK_CONFIG_OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
endif ()
if ( LibKrb5_INCLUDE_DIR )
    set(ZEEK_CONFIG_LibKrb5_INCLUDE_DIR ${LibKrb5_INCLUDE_DIR})
endif ()
if ( GooglePerftools_INCLUDE_DIR )
    set(ZEEK_CONFIG_GooglePerftools_INCLUDE_DIR ${GooglePerftools_INCLUDE_DIR})
endif ()

set(ZEEK_CONFIG_BTEST_TOOLS_DIR ${ZEEK_ROOT_DIR}/share/btest)
install(DIRECTORY DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config @ONLY)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/zeek-config DESTINATION bin)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cmake DESTINATION share/zeek
        USE_SOURCE_PERMISSIONS
        PATTERN ".git" EXCLUDE)

# Install wrapper script for Bro-to-Zeek renaming.
include(InstallShellScript)
include(InstallSymlink)
InstallShellScript("bin" "zeek-wrapper.in" "zeek-wrapper")
InstallSymlink("${CMAKE_INSTALL_PREFIX}/bin/zeek-wrapper" "${CMAKE_INSTALL_PREFIX}/bin/bro-config")

########################################################################
## zkg configuration

if ( INSTALL_ZKG )
    # An etc/zkg directory for zkg's config file simplifies zkg's
    # config file code.
    set(ZEEK_ZKG_CONFIG_DIR "${ZEEK_ETC_INSTALL_DIR}/zkg")
    set(ZEEK_ZKG_STATE_DIR "${ZEEK_ROOT_DIR}/var/lib/zkg")

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/zkg-config.in
        ${CMAKE_CURRENT_BINARY_DIR}/zkg-config @ONLY)

    install(DIRECTORY DESTINATION var/lib/zkg)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zkg-config
        DESTINATION ${ZEEK_ZKG_CONFIG_DIR} RENAME config)
endif ()

########################################################################
## Look for external plugins to build in

string(REPLACE "," " " _build_in_plugins "${ZEEK_INCLUDE_PLUGINS}")
separate_arguments(_build_in_plugins)
foreach(plugin_dir ${_build_in_plugins})
    if ( NOT IS_ABSOLUTE "${plugin_dir}/CMakeLists.txt" )
      message(FATAL_ERROR "Plugins to build in need to be defined with absolute path! ${plugin_dir}")
    endif()

    if ( NOT EXISTS "${plugin_dir}/CMakeLists.txt" )
      message(FATAL_ERROR "No plugin found at ${plugin_dir}!")
    endif()

    get_filename_component(plugin_name ${plugin_dir} NAME)

    # Create a list of plugin directories that will then be added in the src/CMakeLists.txt
    list(APPEND BUILTIN_PLUGIN_LIST ${plugin_dir})

    message(STATUS "  Building in plugin: ${plugin_name} (${plugin_dir})")

    if ( "${ZEEK_BUILTIN_PLUGINS}" STREQUAL "" )
        set(ZEEK_BUILTIN_PLUGINS ${plugin_name})
    else ()
        set(ZEEK_BUILTIN_PLUGINS "${ZEEK_BUILTIN_PLUGINS}, ${plugin_name}")
    endif ()
endforeach()

########################################################################
## Recurse on sub-directories

add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(man)
add_subdirectory(testing)

include(CheckOptionalBuildSources)

CheckOptionalBuildSources(auxil/btest BTest INSTALL_BTEST)
CheckOptionalBuildSources(auxil/package-manager ZKG INSTALL_ZKG)
CheckOptionalBuildSources(auxil/zeekctl   ZeekControl INSTALL_ZEEKCTL)
CheckOptionalBuildSources(auxil/zeek-aux  Zeek-Aux  INSTALL_AUX_TOOLS)
CheckOptionalBuildSources(auxil/zeek-archiver ZeekArchiver INSTALL_ZEEK_ARCHIVER)
CheckOptionalBuildSources(auxil/zeek-client ZeekClient INSTALL_ZEEK_CLIENT)

########################################################################
## Packaging Setup

if ( INSTALL_ZEEKCTL OR INSTALL_ZKG OR INSTALL_ZEEK_CLIENT )
    # CPack RPM Generator may not automatically detect this
    set(CPACK_RPM_PACKAGE_REQUIRES "python >= ${ZEEK_PYTHON_MIN}")
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

if ( INSTALL_BTEST_PCAPS )
    set(_install_btest_tools_msg "all")
else ()
    set(_install_btest_tools_msg "no pcaps")
endif ()

message(
    "\n====================|  Zeek Build Summary  |===================="
    "\n"
    "\nBuild type:        ${CMAKE_BUILD_TYPE}"
    "\nBuild dir:         ${PROJECT_BINARY_DIR}"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nPlugin dir:        ${BRO_PLUGIN_INSTALL_PATH}"
    "\nPython module dir: ${PY_MOD_INSTALL_DIR}"
    "\nZeek Script Path:  ${ZEEK_SCRIPT_INSTALL_PATH}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nUnit tests:        ${ENABLE_ZEEK_UNIT_TESTS}"
    "\nBuiltin Plugins:   ${ZEEK_BUILTIN_PLUGINS}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nZeekControl:       ${INSTALL_ZEEKCTL}"
    "\nAux. Tools:        ${INSTALL_AUX_TOOLS}"
    "\nBTest:             ${INSTALL_BTEST}"
    "\nBTest tooling:     ${_install_btest_tools_msg}"
    "\nzkg:               ${INSTALL_ZKG}"
    "\n"
    "\nlibmaxminddb:      ${USE_GEOIP}"
    "\nKerberos:          ${USE_KRB5}"
    "\ngperftools found:  ${HAVE_PERFTOOLS}"
    "\n        tcmalloc:  ${USE_PERFTOOLS_TCMALLOC}"
    "\n       debugging:  ${USE_PERFTOOLS_DEBUG}"
    "\njemalloc:          ${ENABLE_JEMALLOC}"
    "\n"
    "\nFuzz Targets:      ${ZEEK_ENABLE_FUZZERS}"
    "\nFuzz Engine:       ${ZEEK_FUZZING_ENGINE}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
