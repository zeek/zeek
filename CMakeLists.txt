# When changing the minimum version here, also adapt
# auxil/zeek-aux/plugin-support/skeleton/CMakeLists.txt
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

if (WIN32)
    # Enable usage of CMAKE_MSVC_RUNTIME_LIBRARY variable
    cmake_policy(SET CMP0091 NEW)

    # I tried to just use CMAKE_SOURCE_DIR and CMAKE_CURRENT_SOURCE_DIR
    # but it's not setting the path correctly and so the toolchain
    # variable doesn't get passed down to submodules like libkqueue
    # correctly. Instead get the absolute path to the vcpkg.cmake file
    # and use that.
    get_filename_component(_toolchain ./auxil/vcpkg/scripts/buildsystems/vcpkg.cmake ABSOLUTE)

    # This needs to happen before the project() call below so that it
    # doesn't need to be manually passed on the command line.
    set(CMAKE_TOOLCHAIN_FILE ${_toolchain} CACHE STRING "Vcpkg toolchain file")
endif ()

project(Zeek C CXX)

# We want to set ENABLE_DEBUG to ON by default if the build type is Debug.
set(ENABLE_DEBUG_DEFAULT OFF)
if (NOT GENERATOR_IS_MULTI_CONFIG)
    string(TOLOWER "${CMAKE_BUILD_TYPE}" _build_type_lower)
    if (_build_type_lower STREQUAL "debug")
        set(ENABLE_DEBUG_DEFAULT ON)
    endif ()
    unset(_build_type_lower)
endif ()

# On UNIX, install additional Zeek tools by default and build shared objects.
if (NOT WIN32)
    set(ZEEK_INSTALL_TOOLS_DEFAULT ON)
    option(BUILD_SHARED_LIBS "Build targets as shared libraries." ON)
else ()
    set(ZEEK_INSTALL_TOOLS_DEFAULT OFF)
endif ()

# CMake options (Boolean flags).
option(ENABLE_DEBUG "Build Zeek with additional debugging support." ${ENABLE_DEBUG_DEFAULT})
option(ENABLE_JEMALLOC "Link against jemalloc." OFF)
option(ENABLE_PERFTOOLS "Build with support for Google perftools." OFF)
option(ENABLE_ZEEK_UNIT_TESTS "Build the C++ unit tests." ON)
option(INSTALL_AUX_TOOLS "Install additional tools from auxil." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(INSTALL_BTEST "Install btest alongside Zeek." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(INSTALL_BTEST_PCAPS "Install pcap files for testing." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(INSTALL_ZEEKCTL "Install zeekctl." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(INSTALL_ZEEK_ARCHIVER "Install the zeek-archiver." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(INSTALL_ZEEK_CLIENT "Install the zeek-client." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(INSTALL_ZKG "Install zkg." ${ZEEK_INSTALL_TOOLS_DEFAULT})
option(PREALLOCATE_PORT_ARRAY "Pre-allocate all ports for zeek::Val." ON)
option(ZEEK_STANDALONE "Build Zeek as stand-alone binary?" ON)

# Non-boolean options.
if (NOT WIN32)
    if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX "/usr/local/zeek"
            CACHE PATH "Install directory used by install()." FORCE)
    endif ()
    # On windows, this defaults to "c:/Program Files/${PROJECT_NAME}":
    # https://cmake.org/cmake/help/v3.15/variable/CMAKE_INSTALL_PREFIX.html.
endif ()

set(ZEEK_SCRIPT_INSTALL_PATH "${CMAKE_INSTALL_PREFIX}/share/zeek"
    CACHE PATH "Install directory for Zeek scripts.")

set(ZEEK_ETC_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/etc"
    CACHE PATH "Install directory for Zeek configuration files.")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL
                                           "Whether to write a JSON compile commands database")

set(ZEEK_CXX_STD cxx_std_17 CACHE STRING "The C++ standard to use.")

set(ZEEK_SANITIZERS "" CACHE STRING "Sanitizers to use when building.")

set(CPACK_SOURCE_IGNORE_FILES "" CACHE STRING "Files to be ignored by CPack")

set(ZEEK_INCLUDE_PLUGINS "" CACHE STRING "Extra plugins to add to the build.")

# Look into the build tree for additional CMake modules.
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

# Windows: Configure runtime and dependencies
if (MSVC)
    # Remove existing runtime flags
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO)
    foreach (CompilerFlag ${CompilerFlags})
        string(REGEX REPLACE "[/|-]MDd" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]MD" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]MTd" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]MT" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]Zi" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]W3" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]W4" "" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach ()

    # Set compilation flags for Windows
    add_compile_options(
        /guard:cf # required by CheckCFlags
        /Z7 # required by CheckCFlags
        /J # Similar to -funsigned-char on other platforms
        /wd4068) # Disable unknown pragma warnings

    add_link_options(/debug:full # required by CheckCFlags
    )

    # Set always to static runtime
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd /DDEBUG")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")
        set(CMAKE_MSVC_RUNTIME_LIBRARY_FLAG "MTd")
    else ()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
        set(CMAKE_MSVC_RUNTIME_LIBRARY_FLAG "MT")
    endif ()

    set(OPENSSL_USE_STATIC_LIBS true)
    set(OPENSSL_MSVC_STATIC_RT true)

    # Set PCAP_ROOT_DIR to point at the installation from vcpkg. A later call
    # to FindPCAP.cmake will fill in the rest of the necessary variables.
    if (NOT PCAP_ROOT_DIR)
        set(PCAP_ROOT_DIR ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET})
    else ()
        unset(PCAP_INCLUDE_DIR CACHE)
        unset(PCAP_LIBRARY CACHE)
    endif ()

    set(LIBPCAP_PCAP_COMPILE_NOPCAP_HAS_ERROR_PARAMETER false)

    # Find zlib installed by vcpkg.
    find_package(ZLIB)
    set(ZLIB_LIBRARY ZLIB::ZLIB)

    # Find c-ares installed by vcpkg.
    find_package(c-ares)
    set(HAVE_CARES true) # Disable FindCAres cmake file
    include_directories(BEFORE ${c-ares_INCLUDE_DIRS})
    set(zeekdeps ${zeekdeps} c-ares::cares)
    add_definitions(-DCARES_STATICLIB)

    add_subdirectory(auxil/libunistd)
    set(UNISTD_INCLUDES ${CMAKE_SOURCE_DIR}/auxil/libunistd/unistd
                        ${CMAKE_SOURCE_DIR}/auxil/libunistd/regex)
    include_directories(BEFORE ${UNISTD_INCLUDES})

    # Required for `check_include_files` to operate correctly
    list(APPEND CMAKE_REQUIRED_INCLUDES ${UNISTD_INCLUDES})
    list(APPEND zeekdeps libunistd libregex)

    # Set CMAKE flags for supported windows build.
    set(DISABLE_PYTHON_BINDINGS true)
    set(BROKER_DISABLE_TESTS true)
    set(BROKER_DISABLE_DOC_EXAMPLES true)
    add_definitions(-DDOCTEST_CONFIG_NO_MULTITHREADING)

    # Disable Spicy as it is not yet supported in Windows.
    set(DISABLE_SPICY true)

    if (BUILD_WITH_WERROR)
        # TODO: This is disabled for now because there a bunch of known
        # compiler warnings on Windows that we don't have good fixes for.
        #set(WERROR_FLAG "/WX")
        #set(WERROR_FLAG "/WX")
    endif ()
else ()
    include(GNUInstallDirs)
    if (BUILD_WITH_WERROR)
        set(WERROR_FLAG "-Werror")
    endif ()
endif ()

include(cmake/CommonCMakeConfig.cmake)
include(cmake/FindClangTidy.cmake)
include(cmake/CheckCompilerArch.cmake)

string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)

# ##############################################################################
# Main targets and utilities.

# Variable for referring back to Zeek's top-level source dir. Used for plugins
# to tell them where to find the Zeek headers.
set(ZEEK_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# Tell dynamic plugins where to find scripts such as
# zeek-plugin-create-package.sh. Needed by ZeekPluginConfig.cmake.in.
set(ZEEK_PLUGIN_SCRIPTS_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Our C++17 base target for propagating compiler and linker flags. Note: for
# now, we only use it for passing library dependencies around.
add_library(zeek_internal INTERFACE)
add_library(Zeek::Internal ALIAS zeek_internal)
set_target_properties(zeek_internal PROPERTIES EXPORT_NAME Internal)
install(TARGETS zeek_internal EXPORT ZeekTargets)

# Skip "link-time version check" in Plugin.h for plugins that we bake in.
target_compile_definitions(zeek_internal INTERFACE ZEEK_PLUGIN_SKIP_VERSION_CHECK)

# Target for bundling the creation of auto-generated files.
add_custom_target(zeek_autogen_files)

# Define our main targets and place the output files under src (for historic
# reasons and backwards compatibility).
if (ZEEK_STANDALONE)
    add_executable(zeek_exe)
    target_compile_features(zeek_exe PRIVATE ${ZEEK_CXX_STD})
    set_target_properties(zeek_exe PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(zeek_exe PRIVATE $<BUILD_INTERFACE:zeek_internal>)
    add_dependencies(zeek_exe zeek_autogen_files)
    set_target_properties(zeek_exe PROPERTIES RUNTIME_OUTPUT_NAME zeek)
    if (NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
        set_target_properties(zeek_exe PROPERTIES RUNTIME_OUTPUT_DIRECTORY src)
    endif ()
    install(TARGETS zeek_exe RUNTIME DESTINATION bin)
    # Export symbols from zeek executable for use by plugins
    set_target_properties(zeek_exe PROPERTIES ENABLE_EXPORTS ON)
    if (MSVC)
        set(WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif ()
    # Tell zeek_target_link_libraries to add library dependencies as PRIVATE.
    set(zeek_exe_access PRIVATE)
else ()
    add_library(zeek_lib STATIC)
endif ()

if (TARGET zeek_lib)
    target_link_libraries(zeek_lib PRIVATE $<BUILD_INTERFACE:zeek_internal>)
    add_dependencies(zeek_lib zeek_autogen_files)
    set_target_properties(zeek_lib PROPERTIES RUNTIME_OUTPUT_NAME libzeek)
    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set_target_properties(zeek_lib PROPERTIES LIBRARY_OUTPUT_DIRECTORY src)
    endif ()
    install(TARGETS zeek_lib LIBRARY DESTINATION lib)
    # Tell zeek_target_link_libraries to add library dependencies as PRIVATE.
    set(zeek_lib_access PRIVATE)
endif ()

# When building our fuzzers, we also need one extra top-level target that
# bundles all of our object libraries and other dependencies.
if (ZEEK_ENABLE_FUZZERS)
    add_library(zeek_fuzzer_shared SHARED)
    target_compile_features(zeek_fuzzer_shared PRIVATE ${ZEEK_CXX_STD})
    set_target_properties(zeek_fuzzer_shared PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(zeek_fuzzer_shared PUBLIC $<BUILD_INTERFACE:zeek_internal>)
    # Tell zeek_target_link_libraries to add library dependencies as PUBLIC.
    set(zeek_fuzzer_shared_access PUBLIC)
endif ()

# Set ZEEK_CONFIG_SKIP_VERSION_H for our main in-source targets.
foreach (name zeek_exe zeek_lib zeek_fuzzer_shared)
    if (TARGET ${name})
        target_compile_definitions(${name} PRIVATE ZEEK_CONFIG_SKIP_VERSION_H)
        target_compile_options(${name} PRIVATE ${WERROR_FLAG})
    endif ()
endforeach ()

# Convenience function for adding library dependencies to the main target(s).
function (zeek_target_link_libraries lib_target)
    foreach (name zeek_exe zeek_lib zeek_fuzzer_shared)
        if (TARGET ${name})
            target_link_libraries(${name} ${${name}_access} ${lib_target})
        endif ()
    endforeach ()
endfunction ()

function (zeek_include_directories)
    foreach (name zeek_exe zeek_lib zeek_fuzzer_shared)
        if (TARGET ${name})
            target_include_directories(${name} ${${name}_access} ${ARGN})
        endif ()
    endforeach ()
endfunction ()

# Convenience function for adding a dependency to the main target(s).
function (zeek_add_dependencies dep)
    foreach (name zeek_exe zeek_lib zeek_fuzzer_shared)
        if (TARGET ${name})
            add_dependencies(${name} ${dep})
        endif ()
    endforeach ()
endfunction ()

# Interface library for propagating extra flags and include paths to dynamically
# loaded plugins. Also propagates include paths and C++17 mode on the install
# interface.
add_library(zeek_dynamic_plugin_base INTERFACE)
target_include_directories(
    zeek_dynamic_plugin_base
    INTERFACE $<INSTALL_INTERFACE:include> $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
              $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_link_libraries(zeek_dynamic_plugin_base INTERFACE Threads::Threads)
add_library(Zeek::DynamicPluginBase ALIAS zeek_dynamic_plugin_base)
set_target_properties(zeek_dynamic_plugin_base PROPERTIES EXPORT_NAME DynamicPluginBase)
install(TARGETS zeek_dynamic_plugin_base EXPORT ZeekTargets)

# On macOS, we need to tell the linker that the modules are allowed to have
# undefined symbols.
if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    target_link_options(zeek_dynamic_plugin_base INTERFACE -undefined dynamic_lookup
                        -Wl,-bind_at_load)
endif ()

function (add_zeek_dynamic_plugin_build_interface_include_directories)
    foreach (path ${ARGV})
        target_include_directories(zeek_dynamic_plugin_base INTERFACE $<BUILD_INTERFACE:${path}>)
    endforeach ()
endfunction ()

add_zeek_dynamic_plugin_build_interface_include_directories(
    ${PROJECT_SOURCE_DIR}/src/include
    ${PROJECT_SOURCE_DIR}/auxil/binpac/lib
    ${PROJECT_SOURCE_DIR}/auxil/broker/libbroker
    ${PROJECT_SOURCE_DIR}/auxil/paraglob/include
    ${PROJECT_SOURCE_DIR}/auxil/rapidjson/include
    ${CMAKE_BINARY_DIR}/src
    ${CMAKE_BINARY_DIR}/src/include
    ${CMAKE_BINARY_DIR}/auxil/binpac/lib
    ${CMAKE_BINARY_DIR}/auxil/broker/libbroker)

# threading/formatters/JSON.h includes rapidjson headers and may be used
# by external plugins, extend the include path.
target_include_directories(zeek_dynamic_plugin_base SYSTEM
                           INTERFACE $<INSTALL_INTERFACE:include/zeek/3rdparty/rapidjson/include>)

# Convenience function for adding an OBJECT library that feeds directly into the
# main target(s).
#
# Usage: zeek_add_subdir_library( <name> SOURCES ... [INCLUDE_DIRS ...]
# [DEPENDENCIES ...] [INTERNAL_DEPENDENCIES ...] [BIFS ...] )
function (zeek_add_subdir_library name)
    # Parse arguments.
    set(fn_varargs INCLUDE_DIRS DEPENDENCIES INTERNAL_DEPENDENCIES SOURCES BIFS)
    cmake_parse_arguments(FN_ARGS "" "" "${fn_varargs}" ${ARGN})
    if (NOT FN_ARGS_SOURCES)
        message(FATAL_ERROR "zeek_add_subdir_library called without any SOURCES")
    endif ()

    # Create target and add the sources.
    set(target_name "zeek_${name}_obj")
    add_library(${target_name} OBJECT ${FN_ARGS_SOURCES})
    target_compile_features(${target_name} PRIVATE ${ZEEK_CXX_STD})
    set_target_properties(${target_name} PROPERTIES CXX_EXTENSIONS OFF)
    target_compile_definitions(${target_name} PRIVATE ZEEK_CONFIG_SKIP_VERSION_H)
    add_dependencies(${target_name} zeek_autogen_files)
    target_link_libraries(${target_name} PRIVATE $<BUILD_INTERFACE:zeek_internal>)
    add_clang_tidy_files(${FN_ARGS_SOURCES})
    target_compile_options(${target_name} PRIVATE ${WERROR_FLAG})

    # Take care of compiling BIFs.
    if (FN_ARGS_BIFS)
        foreach (bif ${FN_ARGS_BIFS})
            # Generate the target and add the extra dependency.
            bif_target(${bif})
        endforeach ()
    endif ()

    # Optionally add include directories and extra dependencies.
    if (FN_ARGS_INCLUDE_DIRS)
        target_include_directories(${target_name} BEFORE PRIVATE ${FN_ARGS_INCLUDE_DIRS})
    endif ()
    if (FN_ARGS_DEPENDENCIES)
        target_link_libraries(${target_name} PRIVATE ${FN_ARGS_DEPENDENCIES})
    endif ()
    if (FN_ARGS_INTERNAL_DEPENDENCIES)
        add_dependencies(${target_name} ${FN_ARGS_INTERNAL_DEPENDENCIES})
    endif ()

    # Feed into the main Zeek target(s).
    zeek_target_link_libraries(${target_name})
endfunction ()

# ##############################################################################
# Utility function for forcing CMake to re-run if files change on disk.

function (zeek_watch_files)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${ARGN})
endfunction ()

# ##############################################################################
# Create empty __load__.zeek stubs (override pre-existing ones).

function (zeek_create_load_script_stubs)
    set(file_comment "# Warning, this is an autogenerated file!\n")
    foreach (fpath ${ARGN})
        file(WRITE "${CMAKE_BINARY_DIR}/${fpath}" "${file_comment}")
        zeek_watch_files("${CMAKE_BINARY_DIR}/${fpath}")
    endforeach ()
endfunction ()

# Note: these files are filled from BifCl.cmake via `file(APPEND ...)`
zeek_create_load_script_stubs(scripts/builtin-plugins/__load__.zeek
                              scripts/base/bif/plugins/__load__.zeek scripts/base/bif/__load__.zeek)

# ##############################################################################
# Create empty __all__*.cc stubs (override pre-existing ones).

function (zeek_create_bif_autogen_stubs)
    set(file_comment "// Warning, this is an autogenerated file!\n")
    foreach (fpath ${ARGN})
        file(WRITE "${CMAKE_BINARY_DIR}/${fpath}" "${file_comment}")
        zeek_watch_files("${CMAKE_BINARY_DIR}/${fpath}")
    endforeach ()
endfunction ()

# Note: these files are filled from BifCl.cmake via `file(APPEND ...)`.
zeek_create_bif_autogen_stubs(src/__all__.bif.cc src/__all__.bif.init.cc
                              src/__all__.bif.register.cc)

# ##############################################################################
# Project/Build Configuration

if (ZEEK_ENABLE_FUZZERS)
    # Fuzzers use shared lib to save disk space, so need -fPIC on everything
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif ()

if (ENABLE_ZEEK_UNIT_TESTS)
    enable_testing()
    add_definitions(-DDOCTEST_CONFIG_SUPER_FAST_ASSERTS)
    target_compile_definitions(zeek_dynamic_plugin_base INTERFACE DOCTEST_CONFIG_SUPER_FAST_ASSERTS)
else ()
    add_definitions(-DDOCTEST_CONFIG_DISABLE)
    target_compile_definitions(zeek_dynamic_plugin_base INTERFACE DOCTEST_CONFIG_DISABLE)
endif ()

if (ENABLE_CCACHE)
    find_program(CCACHE_PROGRAM ccache)

    if (NOT CCACHE_PROGRAM)
        message(FATAL_ERROR "ccache not found")
    endif ()

    message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
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

# sanitize the Zeek script install directory into an absolute path (CMake is
# confused by ~ as a representation of home directory)
get_filename_component(ZEEK_SCRIPT_INSTALL_PATH ${ZEEK_SCRIPT_INSTALL_PATH} ABSOLUTE)

# A folder for library-like Zeek-specific things: Python modules, Zeek plugins,
# etc.
set(ZEEK_LIBDIR_PATH ${CMAKE_INSTALL_FULL_LIBDIR}/zeek)

if (NOT ZEEK_PLUGIN_DIR)
    set(ZEEK_PLUGIN_DIR ${ZEEK_LIBDIR_PATH}/plugins CACHE STRING "Installation path for plugins"
                                                          FORCE)
endif ()

set(cmake_binary_dir "${CMAKE_BINARY_DIR}")
set(cmake_current_binary_dir "${CMAKE_CURRENT_BINARY_DIR}")
set(cmake_install_prefix "${CMAKE_INSTALL_PREFIX}")
set(cmake_source_dir "${CMAKE_SOURCE_DIR}")
set(zeek_script_install_path "${ZEEK_SCRIPT_INSTALL_PATH}")
if (MSVC)
    # This has to happen before we modify the paths below so that the pure Windows
    # paths are stored in the output file.
    configure_file(cmake_templates/zeek-path-dev.bat.in
                   ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.bat)

    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_binary_dir "${cmake_binary_dir}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_current_binary_dir
                         "${cmake_current_binary_dir}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_install_prefix
                         "${cmake_install_prefix}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_source_dir "${cmake_source_dir}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" zeek_script_install_path
                         "${zeek_script_install_path}")
endif ()

# Set the path where we install the ZeekConfig.cmake file and related files.
set(ZEEK_CMAKE_CONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/zeek/cmake")

if (NOT ZEEK_ETC_INSTALL_DIR)
    set(ZEEK_ETC_INSTALL_DIR ${ZEEK_ROOT_DIR}/etc)
endif ()

if (NOT ZEEK_STATE_DIR)
    set(ZEEK_STATE_DIR ${ZEEK_ROOT_DIR}/var/lib)
endif ()

if (NOT ZEEK_SPOOL_DIR)
    set(ZEEK_SPOOL_DIR ${ZEEK_ROOT_DIR}/spool)
endif ()

if (NOT ZEEK_LOG_DIR)
    set(ZEEK_LOG_DIR ${ZEEK_ROOT_DIR}/logs)
endif ()

if (NOT MSVC)
    set(HAVE_SUPERVISOR true)
endif ()

install(DIRECTORY DESTINATION ${ZEEK_ETC_INSTALL_DIR})
install(DIRECTORY DESTINATION ${ZEEK_STATE_DIR})
install(DIRECTORY DESTINATION ${ZEEK_SPOOL_DIR})
install(DIRECTORY DESTINATION ${ZEEK_LOG_DIR})

configure_file(cmake_templates/zeek-path-dev.in ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev)

file(
    WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.sh
    "export ZEEKPATH=`${cmake_binary_dir}/zeek-path-dev`\n"
    "export ZEEK_PLUGIN_PATH=\"${cmake_binary_dir}/src\":$\{ZEEK_PLUGIN_PATH\}\n"
    "export PATH=\"${cmake_binary_dir}\":\"${cmake_binary_dir}/src\":\"${cmake_binary_dir}/auxil/spicy/bin\":\"${cmake_binary_dir}/src/spicy/spicyz\":$\{PATH\}\n"
    "export SPICY_PATH=`${cmake_binary_dir}/spicy-path`\n"
    "export HILTI_CXX_INCLUDE_DIRS=`${cmake_binary_dir}/hilti-cxx-include-dirs`\n"
    "export ZEEK_SPICY_LIBRARY_PATH=${cmake_source_dir}/scripts/spicy\n"
    "export SPICY_BUILD_DIRECTORY=${cmake_binary_dir}/auxil/spicy\n")

file(
    WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.csh
    "setenv ZEEKPATH `${cmake_binary_dir}/zeek-path-dev`\n"
    "setenv ZEEK_PLUGIN_PATH \"${cmake_binary_dir}/src\":$\{ZEEK_PLUGIN_PATH\}\n"
    "setenv PATH \"${cmake_binary_dir}\":\"${cmake_binary_dir}/src\":\"${cmake_binary_dir}/auxil/spicy/bin\":\"${cmake_binary_dir}/src/spicy/spicyz\":$\{PATH\}\n"
    "setenv SPICY_PATH \"`${cmake_binary_dir}/spicy-path`\"\n"
    "setenv HILTI_CXX_INCLUDE_DIRS \"`${cmake_binary_dir}/hilti-cxx-include-dirs`\"\n"
    "setenv ZEEK_SPICY_LIBRARY_PATH \"${cmake_source_dir}/scripts/spicy\"\n"
    "setenv SPICY_BUILD_DIRECTORY \"${cmake_binary_dir}/auxil/spicy\"\n")

if (CMAKE_CXX_COMPILER_LAUNCHER)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.sh
         "export HILTI_CXX_COMPILER_LAUNCHER=${CMAKE_CXX_COMPILER_LAUNCHER}\n")

    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.csh
         "setenv HILTI_CXX_COMPILER_LAUNCHER=${CMAKE_CXX_COMPILER_LAUNCHER}\n")
endif ()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ZEEK_VERSION_FULL LIMIT_COUNT 1)

execute_process(
    COMMAND grep "^constexpr int PLUGIN_API_VERSION"
    INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/plugin/Plugin.h
    OUTPUT_VARIABLE API_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)

string(REGEX MATCH "^constexpr int PLUGIN_API_VERSION = ([0-9]+);" API_VERSION "${API_VERSION}")
set(API_VERSION "${CMAKE_MATCH_1}")

string(REGEX REPLACE "[.-]" " " version_numbers ${ZEEK_VERSION_FULL})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)
set(VERSION_MAJ_MIN "${VERSION_MAJOR}.${VERSION_MINOR}")
math(EXPR ZEEK_VERSION_NUMBER
     "${VERSION_MAJOR} * 10000 + ${VERSION_MINOR} * 100 + ${VERSION_PATCH}")

set(VERSION_C_IDENT "${ZEEK_VERSION_FULL}_plugin_${API_VERSION}")
string(REGEX REPLACE "-[0-9]*$" "_git" VERSION_C_IDENT "${VERSION_C_IDENT}")
string(REGEX REPLACE "[^a-zA-Z0-9_\$]" "_" VERSION_C_IDENT "${VERSION_C_IDENT}")

if (ENABLE_DEBUG)
    set(VERSION_C_IDENT "${VERSION_C_IDENT}_debug")
    target_compile_definitions(zeek_internal INTERFACE DEBUG)
    target_compile_definitions(zeek_dynamic_plugin_base INTERFACE DEBUG)
endif ()

if (NOT BINARY_PACKAGING_MODE)
    macro (_make_install_dir_symlink _target _link)
        install(
            CODE "
        if ( \"\$ENV{DESTDIR}\" STREQUAL \"\" )
          if ( EXISTS \"${_target}\" AND NOT EXISTS \"${_link}\" )
            message(STATUS \"WARNING: installed ${_link} as symlink to ${_target}\")
            execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
              \"${_target}\" \"${_link}\")
          endif ()
        endif ()
      ")
    endmacro ()

    if ("${CMAKE_INSTALL_PREFIX}" STREQUAL "/usr/local/zeek")
        # If we're installing into the default prefix, check if the old default
        # prefix already exists and symlink to it. This is done to help keep custom
        # user configuration/installation if they're upgrading from a version before
        # Zeek 3.0.
        _make_install_dir_symlink("/usr/local/bro" "/usr/local/zeek")
    endif ()

    # Check whether we need to symlink directories used by versions before Zeek
    # 3.0.
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/include/bro"
                              "${CMAKE_INSTALL_PREFIX}/include/zeek")
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/share/bro"
                              "${CMAKE_INSTALL_PREFIX}/share/zeek")
    _make_install_dir_symlink("${CMAKE_INSTALL_PREFIX}/lib/bro" "${CMAKE_INSTALL_FULL_LIBDIR}/zeek")
endif ()

if (ZEEK_SANITIZERS)
    # Check the thread library info early as setting compiler flags seems to
    # interfere with the detection and cause CMAKE_THREAD_LIBS_INIT to not include
    # -lpthread when it should.
    find_package(Threads)

    string(REPLACE "," " " _sanitizer_args "${ZEEK_SANITIZERS}")
    separate_arguments(_sanitizer_args)
    set(ZEEK_SANITIZERS "")

    foreach (_sanitizer ${_sanitizer_args})
        if (ZEEK_SANITIZERS)
            set(ZEEK_SANITIZERS "${ZEEK_SANITIZERS},")
        endif ()

        if (_sanitizer STREQUAL "thread")
            set(ZEEK_TSAN true)
        endif ()

        if (NOT _sanitizer STREQUAL "undefined")
            set(ZEEK_SANITIZERS "${ZEEK_SANITIZERS}${_sanitizer}")
            continue()
        endif ()

        if (NOT DEFINED ZEEK_SANITIZER_UB_CHECKS)
            if (DEFINED ENV{ZEEK_TAILORED_UB_CHECKS})
                # list(APPEND _check_list "alignment") # TODO: fix associated errors
                list(APPEND _check_list "bool")
                # list(APPEND _check_list "builtin") # Not implemented in older GCCs
                list(APPEND _check_list "bounds") # Covers both array/local bounds
                                                  # options below
                # list(APPEND _check_list "array-bounds") # Not implemented by GCC
                # list(APPEND _check_list "local-bounds") # Not normally part of
                # "undefined"
                list(APPEND _check_list "enum")
                list(APPEND _check_list "float-cast-overflow")
                list(APPEND _check_list "float-divide-by-zero")
                # list(APPEND _check_list "function") # Not implemented by GCC
                # list(APPEND _check_list "implicit-unsigned-integer-truncation") # Not
                # truly UB list(APPEND _check_list "implicit-signed-integer-truncation")
                # # Not truly UB list(APPEND _check_list "implicit-integer-sign-change")
                # # Not truly UB
                list(APPEND _check_list "integer-divide-by-zero")
                list(APPEND _check_list "nonnull-attribute")
                list(APPEND _check_list "null")
                # list(APPEND _check_list "nullability-arg") # Not normally part of
                # "undefined" list(APPEND _check_list "nullability-assign") # Not
                # normally part of "undefined" list(APPEND _check_list
                # "nullability-return") # Not normally part of "undefined" list(APPEND
                # _check_list "objc-cast") # Not truly UB list(APPEND _check_list
                # "pointer-overflow") # Not implemented in older GCCs
                list(APPEND _check_list "return")
                list(APPEND _check_list "returns-nonnull-attribute")
                list(APPEND _check_list "shift")
                # list(APPEND _check_list "unsigned-shift-base") # Not implemented by
                # GCC
                list(APPEND _check_list "signed-integer-overflow")
                list(APPEND _check_list "unreachable")
                # list(APPEND _check_list "unsigned-integer-overflow") # Not truly UB
                list(APPEND _check_list "vla-bound")
                list(APPEND _check_list "vptr")

                # Clang complains if this one is defined and the optimizer is set to
                # -O0. We only set that optimization level if NO_OPTIMIZATIONS is
                # passed, so disable the option if that's set.
                if (NOT DEFINED ENV{NO_OPTIMIZATIONS})
                    list(APPEND _check_list "object-size")
                endif ()

                string(REPLACE ";" "," _ub_checks "${_check_list}")
                set(ZEEK_SANITIZER_UB_CHECKS "${_ub_checks}" CACHE INTERNAL "" FORCE)
            else ()
                set(ZEEK_SANITIZER_UB_CHECKS "undefined" CACHE INTERNAL "" FORCE)
            endif ()
        endif ()

        set(ZEEK_SANITIZERS "${ZEEK_SANITIZERS}${ZEEK_SANITIZER_UB_CHECKS}")
    endforeach ()

    set(_sanitizer_flags "-fsanitize=${ZEEK_SANITIZERS}")

    # The linker command used by check_cxx_compiler_flag requires you to also pass
    # the sanitizer to it or it fails. The best way to do this is to set
    # CMAKE_REQUIRED_LINK_OPTIONS, but save off a copy of it so it can be reset
    # back to what it was previously afterwards.
    set(_temp_link_options ${CMAKE_REQUIRED_LINK_OPTIONS})
    list(APPEND CMAKE_REQUIRED_LINK_OPTIONS ${_sanitizer_flags})
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(${_sanitizer_flags} COMPILER_SUPPORTS_SANITIZERS)
    if (NOT COMPILER_SUPPORTS_SANITIZERS)
        message(FATAL_ERROR "Invalid sanitizer compiler flags: ${_sanitizer_flags}")
    endif ()
    set(CMAKE_REQUIRED_LINK_OPTIONS ${_temp_link_options})

    if (ZEEK_SANITIZER_UB_CHECKS)
        set(_sanitizer_flags
            "${_sanitizer_flags} -fno-sanitize-recover=${ZEEK_SANITIZER_UB_CHECKS}")
    endif ()

    set(_sanitizer_flags "${_sanitizer_flags} -fno-omit-frame-pointer")
    set(_sanitizer_flags "${_sanitizer_flags} -fno-optimize-sibling-calls")

    if (NOT DEFINED ZEEK_SANITIZER_OPTIMIZATIONS)
        if (DEFINED ENV{NO_OPTIMIZATIONS})
            # Using -O1 is generally the suggestion to get more reasonable
            # performance.  The one downside is it that the compiler may optimize out
            # code that otherwise generates an error/leak in a -O0 build, but that
            # should be rare and users mostly will not be running unoptimized builds
            # in production anyway.
            set(ZEEK_SANITIZER_OPTIMIZATIONS false CACHE INTERNAL "" FORCE)
        else ()
            set(ZEEK_SANITIZER_OPTIMIZATIONS true CACHE INTERNAL "" FORCE)
        endif ()
    endif ()

    if (ZEEK_SANITIZER_OPTIMIZATIONS)
        set(_sanitizer_flags "${_sanitizer_flags} -O1")
    endif ()

    # Technically, the we also need to use the compiler to drive linking and give
    # the sanitizer flags there, too.  However, CMake, by default, uses the
    # compiler for linking and so the automatically flags get used.  See
    # https://cmake.org/pipermail/cmake/2014-August/058268.html
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_sanitizer_flags}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_sanitizer_flags}")
endif ()

# ##############################################################################
# Dependency Configuration

# Check cache value first to avoid displaying "Found sed" messages everytime
if (NOT SED_EXE)
    find_program(SED_EXE sed)
    if (NOT SED_EXE)
        message(FATAL_ERROR "Could not find required dependency: sed")
    else ()
        message(STATUS "Found sed: ${SED_EXE}")
    endif ()
endif ()

set(ZEEK_PYTHON_MIN 3.5.0)
set(Python_FIND_UNVERSIONED_NAMES FIRST)
find_package(Python ${ZEEK_PYTHON_MIN} REQUIRED COMPONENTS Interpreter)
find_package(FLEX REQUIRED)
find_package(BISON 2.5 REQUIRED)
find_package(PCAP REQUIRED)
find_package(OpenSSL REQUIRED)
if (NOT MSVC)
    find_package(BIND REQUIRED)
endif ()
find_package(ZLIB REQUIRED)

if (NOT BINARY_PACKAGING_MODE)
    # TODO: Broker seems to always turn on static libraries. We don't want that for Spicy by default.
    set(BUILD_SHARED_LIBS yes)
endif ()

# Forward user-defined hint for OpenSSL to the plugins. Use a cache variable to
# make sure this variable survives CMake re-runs. Note: This variable is picked
# up in ZeekPluginConfig.cmake.in and ZeekConfig.cmake.in.
if (OPENSSL_ROOT_DIR)
    set(ZeekOpenSSLHint "${OPENSSL_ROOT_DIR}" CACHE INTERNAL "" FORCE)
elseif (DEFINED ENV{OPENSSL_ROOT_DIR})
    set(ZeekOpenSSLHint "$ENV{OPENSSL_ROOT_DIR}" CACHE INTERNAL "" FORCE)
endif ()

# Forward PKG_CONFIG_PATH to the plugins. Use a cache variable to make sure this
# variable survives CMake re-runs. Note: This variable is picked up in
# ZeekPluginConfig.cmake.in.
if (DEFINED ENV{PKG_CONFIG_PATH})
    set(ZeekPkgConfigPath "$ENV{PKG_CONFIG_PATH}" CACHE INTERNAL "" FORCE)
endif ()

# Installation directory for the distribution's Python modules. An override via
# configure's --python-dir wins, specifying a directory explicitly. Next is
# --python-prefix, which includes a versioned Python folder as the --prefix
# option in distutils does. Next consider a distutils --home style override via
# --python-home, and finally default to "zeek/python" in our libdir.
if (ZEEK_PYTHON_DIR)
    set(py_mod_install_dir ${ZEEK_PYTHON_DIR})
elseif (ZEEK_PYTHON_PREFIX)
    set(pyver ${Python_VERSION_MAJOR}.${Python_VERSION_MINOR})
    set(py_mod_install_dir ${ZEEK_PYTHON_PREFIX}/lib/python${pyver}/site-packages)
elseif (ZEEK_PYTHON_HOME)
    set(py_mod_install_dir ${ZEEK_PYTHON_HOME}/lib/python)
else ()
    set(py_mod_install_dir ${ZEEK_LIBDIR_PATH}/python)
endif ()
set(PY_MOD_INSTALL_DIR ${py_mod_install_dir} CACHE STRING "Installation path for Python modules"
                                                   FORCE)

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/auxil/binpac/CMakeLists.txt)

    set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})
    if (MSVC)
        set(BUILD_STATIC_BINPAC true)
    endif ()

    if (BUILD_STATIC_BINPAC)
        set(ENABLE_STATIC_ONLY true)
    endif ()

    add_subdirectory(auxil/binpac)
    set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})

    # FIXME: avoid hard-coding a path for multi-config generator support. See the
    # TODO in ZeekPluginConfig.cmake.in.
    set(BINPAC_EXE_PATH "${CMAKE_BINARY_DIR}/auxil/binpac/src/binpac${CMAKE_EXECUTABLE_SUFFIX}")
endif ()

find_package(BinPAC REQUIRED)

# Add an alias (used by our plugin setup).
add_executable(Zeek::BinPAC ALIAS binpac)

if (NOT BIFCL_EXE_PATH)
    add_subdirectory(auxil/bifcl)
    add_executable(Zeek::BifCl ALIAS bifcl)
    # FIXME: avoid hard-coding a path for multi-config generator support. See the
    # TODO in ZeekPluginConfig.cmake.in.
    set(BIFCL_EXE_PATH "${CMAKE_BINARY_DIR}/auxil/bifcl/bifcl${CMAKE_EXECUTABLE_SUFFIX}")
    set(_bifcl_exe_path "included")
else ()
    add_executable(Zeek::BifCl IMPORTED)
    set_property(TARGET Zeek::BifCl PROPERTY IMPORTED_LOCATION "${BIFCL_EXE_PATH}")
    set(_bifcl_exe_path "BIFCL_EXE_PATH")
endif ()

if (NOT GEN_ZAM_EXE_PATH)
    add_subdirectory(auxil/gen-zam)
endif ()

if (ENABLE_JEMALLOC)
    if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        if (DEFINED JEMALLOC_ROOT_DIR)
            # Look for jemalloc at a specific path
            find_package(JeMalloc)
        else ()
            # jemalloc is in the base system
            set(JEMALLOC_FOUND true)
        endif ()
    else ()
        find_package(JeMalloc)
    endif ()

    if (NOT JEMALLOC_FOUND)
        message(FATAL_ERROR "Could not find requested JeMalloc")
    endif ()
endif ()

add_subdirectory(auxil/paraglob)
if (MSVC)
    cmake_policy(SET CMP0079 NEW)
    target_link_libraries(paraglob shlwapi)
    set(BROKER_DISABLE_TOOLS true)
endif ()
set(zeekdeps ${zeekdeps} paraglob)

# Note: Broker gets some special attention in ZeekConfig.cmake.in.
if (Broker_ROOT)
    find_package(Broker REQUIRED CONFIG)
    list(APPEND zeekdeps ${BROKER_LIBRARY})
    set(broker_includes ${BROKER_INCLUDE_DIR})
    set(ZEEK_HAS_EXTERNAL_BROKER ON)
    set(ZEEK_HAS_STATIC_BROKER OFF)
else ()
    if (ZEEK_SANITIZERS)
        set(BROKER_SANITIZERS ${ZEEK_SANITIZERS})
    endif ()

    set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})
    if (MSVC)
        set(BUILD_STATIC_BROKER true)
    endif ()

    if (BUILD_STATIC_BROKER)
        set(ENABLE_STATIC_ONLY true)
    endif ()

    add_subdirectory(auxil/broker)
    set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})

    if (BUILD_STATIC_BROKER)
        list(APPEND zeekdeps broker_static)
    else ()
        list(APPEND zeekdeps broker)
    endif ()

    set(broker_includes ${CMAKE_CURRENT_SOURCE_DIR}/auxil/broker/libbroker
                        ${CMAKE_CURRENT_BINARY_DIR}/auxil/broker/libbroker)

    if (BUILD_STATIC_BROKER)
        set(ZEEK_HAS_STATIC_BROKER ON)
    else ()
        set(ZEEK_HAS_STATIC_BROKER OFF)
    endif ()
    set(ZEEK_HAS_EXTERNAL_BROKER OFF)

    # Tell plugins where to find the Broker CMake package in the source tree. This
    # variable is picked up in ZeekPluginConfig.cmake.in.
    set(ZEEK_PLUGIN_BROKER_PATH "${CMAKE_CURRENT_BINARY_DIR}/auxil/broker")
endif ()

if (NOT DISABLE_SPICY)
    if (SPICY_ROOT_DIR)
        find_package(Spicy REQUIRED) # will set HAVE_SPICY
        spicy_require_version("1.8.0")

        if (NOT SPICY_HAVE_TOOLCHAIN)
            message(FATAL_ERROR "Spicy not built with toolchain support")
        endif ()

        spicy_print_summary()
    else ()
        # Spicy needs the full prefix for Flex and Bison while Zeek captures
        # only the paths to the executables. Derive the prefixes from the
        # binary paths under the assumption that their bindir is under their
        # prefix (which also implies that one such prefix even exists).
        get_filename_component(dir ${FLEX_EXECUTABLE} DIRECTORY ABSOLUTE)
        set(FLEX_ROOT ${dir}/..)

        get_filename_component(dir ${BISON_EXECUTABLE} DIRECTORY ABSOLUTE)
        set(BISON_ROOT ${dir}/..)

        # The script generating precompiled headers for Spicy expects a
        # different build system layout than provided for a bundled Spicy,
        # disable it.
        set(HILTI_DEV_PRECOMPILE_HEADERS OFF)

        # Remove in v6.2. Older versions of Spicy use find_package(Python3),
        # accommodate by setting the Python3_EXECUTABLE hint.
        if (Python_EXECUTABLE)
            set(Python3_EXECUTABLE ${Python_EXECUTABLE} CACHE STRING "Python3_EXECUTABLE hint")
        endif ()

        add_subdirectory(auxil/spicy)
        include(ConfigureSpicyBuild) # set some options different for building Spicy

        zeek_add_dependencies(spicy)

        # Explicitly link against Spicy libraries if we are packaging. Since
        # Zeek's binary packaging mode still leaves `BUILD_SHARED_LIBS` set we
        # cannot use the branching inside `hilti_link_libraries_in_tree` and
        # instead explicitly branch on `BINARY_PACKAGING_MODE` here.
        if (BINARY_PACKAGING_MODE)
            hilti_link_object_libraries_in_tree(zeek_exe PRIVATE)
            spicy_link_object_libraries_in_tree(zeek_exe PRIVATE)
        else ()
            if (TARGET zeek_exe)
                hilti_link_libraries_in_tree(zeek_exe PRIVATE)
                spicy_link_libraries_in_tree(zeek_exe PRIVATE)
            endif ()
            if (TARGET zeek_lib)
                hilti_link_libraries_in_tree(zeek_lib PRIVATE)
                spicy_link_libraries_in_tree(zeek_lib PRIVATE)
            endif ()
        endif ()

        set(HAVE_SPICY yes)
    endif ()

    set(USE_SPICY_ANALYZERS yes)
else ()
    set(HAVE_SPICY no)
    set(USE_SPICY_ANALYZERS no)
endif ()

set(USE_SPICY_ANALYZERS "${USE_SPICY_ANALYZERS}" CACHE BOOL "Use built-in Spicy analyzers")
include(BuiltInSpicyAnalyzer)

include_directories(BEFORE ${PCAP_INCLUDE_DIR} ${BIND_INCLUDE_DIR} ${BinPAC_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIR} ${JEMALLOC_INCLUDE_DIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/auxil/rapidjson/include/rapidjson
        DESTINATION include/zeek/3rdparty/rapidjson/include)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/auxil/filesystem/include/ghc
        DESTINATION include/zeek/3rdparty/)

# Create 3rdparty/ghc within the build directory so that the include for
# "zeek/3rdparty/ghc/filesystem.hpp" works within the build tree.
execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory
                        "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/")
execute_process(
    COMMAND
        "${CMAKE_COMMAND}" -E create_symlink
        "${CMAKE_CURRENT_SOURCE_DIR}/auxil/filesystem/include/ghc"
        "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/ghc")

# Optional Dependencies

set(USE_GEOIP false)
find_package(LibMMDB)
if (LIBMMDB_FOUND)
    set(USE_GEOIP true)
    include_directories(BEFORE ${LibMMDB_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibMMDB_LIBRARY})
endif ()

set(USE_KRB5 false)
if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
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

if (ENABLE_PERFTOOLS)
    find_package(GooglePerftools)

    if (GOOGLEPERFTOOLS_FOUND OR TCMALLOC_FOUND)
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
    else ()
        message(FATAL_ERROR "Could not find requested Google Perftools.")
    endif ()
endif ()

# Making sure any non-standard OpenSSL includes get searched earlier than other
# dependencies which tend to be in standard system locations and thus cause the
# system OpenSSL headers to still be picked up even if one specifies
# --with-openssl (which may be common).
include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})

# Determine if libfts is external to libc, i.e. musl
find_package(FTS)
if (FTS_FOUND)
    list(APPEND OPTLIBS ${FTS_LIBRARY})
    include_directories(BEFORE ${FTS_INCLUDE_DIR})
endif ()

# Any headers that are possibly bundled in the Zeek source-tree and that are
# supposed to have priority over any preexisting/system-wide headers need to
# appear early in compiler search path.
include_directories(BEFORE ${broker_includes})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/auxil/highwayhash)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/auxil/paraglob/include)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/auxil/rapidjson/include)

set(zeekdeps
    ${zeekdeps}
    ${BinPAC_LIBRARY}
    ${PCAP_LIBRARY}
    ${OPENSSL_LIBRARIES}
    ${BIND_LIBRARY}
    ${ZLIB_LIBRARY}
    ${JEMALLOC_LIBRARIES}
    ${OPTLIBS})

# ##############################################################################
# System Introspection

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

# On platforms without a native libkqueue, c-ares is using the existing
# value for HAVE_KQUEUE that was set during the libkqueue setup. We don't
# pass the libkqueue information down to the c-ares cmake run so it won't
# have the paths or library when it builds.
include(FindCAres)
include(FindKqueue)

include_directories(BEFORE "auxil/out_ptr/include")

if ((OPENSSL_VERSION VERSION_EQUAL "1.1.0") OR (OPENSSL_VERSION VERSION_GREATER "1.1.0"))
    set(ZEEK_HAVE_OPENSSL_1_1 true CACHE INTERNAL "" FORCE)
endif ()
if ((OPENSSL_VERSION VERSION_EQUAL "3.0.0") OR (OPENSSL_VERSION VERSION_GREATER "3.0.0"))
    set(ZEEK_HAVE_OPENSSL_3_0 true CACHE INTERNAL "" FORCE)
endif ()

# Tell the plugin code that we're building as part of the main tree.
set(ZEEK_PLUGIN_INTERNAL_BUILD true CACHE INTERNAL "" FORCE)

set(ZEEK_HAVE_AF_PACKET no)
if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
    if (NOT DISABLE_AF_PACKET)
        if (NOT AF_PACKET_PLUGIN_PATH)
            set(AF_PACKET_PLUGIN_PATH ${CMAKE_SOURCE_DIR}/auxil/zeek-af_packet-plugin)
        endif ()

        list(APPEND ZEEK_INCLUDE_PLUGINS ${AF_PACKET_PLUGIN_PATH})
        set(ZEEK_HAVE_AF_PACKET yes)
    endif ()
endif ()

set(ZEEK_HAVE_JAVASCRIPT no)
if (NOT DISABLE_JAVASCRIPT)
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/auxil/zeekjs/cmake)
    find_package(Nodejs)

    if (NODEJS_FOUND)
        if (${NODEJS_VERSION} VERSION_LESS "16.13.0")
            message(
                STATUS
                    "Node.js version ${NODEJS_VERSION} is too old, need 16.13 or later. Not enabling JavaScript support."
            )
        else ()
            set(ZEEKJS_PLUGIN_PATH ${CMAKE_SOURCE_DIR}/auxil/zeekjs)
            list(APPEND ZEEK_INCLUDE_PLUGINS ${ZEEKJS_PLUGIN_PATH})
            set(ZEEK_HAVE_JAVASCRIPT yes)
        endif ()
    endif ()
endif ()

set(ZEEK_HAVE_JAVASCRIPT ${ZEEK_HAVE_JAVASCRIPT} CACHE INTERNAL "Zeek has JavaScript support")

set(DEFAULT_ZEEKPATH_PATHS
    . ${ZEEK_SCRIPT_INSTALL_PATH} ${ZEEK_SCRIPT_INSTALL_PATH}/policy
    ${ZEEK_SCRIPT_INSTALL_PATH}/site ${ZEEK_SCRIPT_INSTALL_PATH}/builtin-plugins)
if (MSVC)
    list(JOIN DEFAULT_ZEEKPATH_PATHS ";" DEFAULT_ZEEKPATH)
else ()
    list(JOIN DEFAULT_ZEEKPATH_PATHS ":" DEFAULT_ZEEKPATH)
endif ()

if (NOT BINARY_PACKAGING_MODE)
    set(ZEEK_DIST ${PROJECT_SOURCE_DIR})
endif ()

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink "." "${CMAKE_CURRENT_BINARY_DIR}/zeek")

if (BinPAC_ROOT_DIR)
    set(ZEEK_CONFIG_BINPAC_ROOT_DIR ${BinPAC_ROOT_DIR})
else ()
    set(ZEEK_CONFIG_BINPAC_ROOT_DIR ${ZEEK_ROOT_DIR})
endif ()

if (BROKER_ROOT_DIR)
    set(ZEEK_CONFIG_BROKER_ROOT_DIR ${BROKER_ROOT_DIR})
else ()
    set(ZEEK_CONFIG_BROKER_ROOT_DIR ${ZEEK_ROOT_DIR})
endif ()

if (PCAP_INCLUDE_DIR)
    set(ZEEK_CONFIG_PCAP_INCLUDE_DIR ${PCAP_INCLUDE_DIR})
endif ()
if (ZLIB_INCLUDE_DIR)
    set(ZEEK_CONFIG_ZLIB_INCLUDE_DIR ${ZLIB_INCLUDE_DIR})
endif ()
if (OPENSSL_INCLUDE_DIR)
    set(ZEEK_CONFIG_OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
endif ()
if (LibKrb5_INCLUDE_DIR)
    set(ZEEK_CONFIG_LibKrb5_INCLUDE_DIR ${LibKrb5_INCLUDE_DIR})
endif ()
if (GooglePerftools_INCLUDE_DIR)
    set(ZEEK_CONFIG_GooglePerftools_INCLUDE_DIR ${GooglePerftools_INCLUDE_DIR})
endif ()

set(ZEEK_CONFIG_BTEST_TOOLS_DIR ${ZEEK_ROOT_DIR}/share/btest)
install(DIRECTORY DESTINATION ${ZEEK_CONFIG_BTEST_TOOLS_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_templates/zeek-config.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config @ONLY)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/zeek-config DESTINATION bin)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cmake
    DESTINATION share/zeek
    USE_SOURCE_PERMISSIONS
    PATTERN ".git" EXCLUDE)

if (NOT MSVC)
    # Install wrapper script for Bro-to-Zeek renaming.
    include(InstallShellScript)
    include(InstallSymlink)
endif ()

# ##############################################################################
# zkg configuration

if (INSTALL_ZKG)
    # An etc/zkg directory for zkg's config file simplifies zkg's config file
    # code.
    set(ZEEK_ZKG_CONFIG_DIR "${ZEEK_ETC_INSTALL_DIR}/zkg")
    set(ZEEK_ZKG_STATE_DIR "${ZEEK_STATE_DIR}/zkg")

    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_templates/zkg-config.in
                   ${CMAKE_CURRENT_BINARY_DIR}/zkg-config @ONLY)

    install(DIRECTORY DESTINATION var/lib/zkg)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zkg-config DESTINATION ${ZEEK_ZKG_CONFIG_DIR}
            RENAME config)
endif ()

# ##############################################################################
# Look for external plugins to build in

string(REPLACE "," " " _build_in_plugins "${ZEEK_INCLUDE_PLUGINS}")
separate_arguments(_build_in_plugins)
foreach (plugin_dir ${_build_in_plugins})
    if (NOT IS_ABSOLUTE "${plugin_dir}/CMakeLists.txt")
        message(
            FATAL_ERROR "Plugins to build in need to be defined with absolute path! ${plugin_dir}")
    endif ()

    if (NOT EXISTS "${plugin_dir}/CMakeLists.txt")
        message(FATAL_ERROR "No plugin found at ${plugin_dir}!")
    endif ()

    get_filename_component(plugin_name ${plugin_dir} NAME)

    # Create a list of plugin directories that will then be added in the
    # src/CMakeLists.txt
    list(APPEND BUILTIN_PLUGIN_LIST ${plugin_dir})

    message(STATUS "  Building in plugin: ${plugin_name} (${plugin_dir})")

    if ("${ZEEK_BUILTIN_PLUGINS}" STREQUAL "")
        set(ZEEK_BUILTIN_PLUGINS ${plugin_name})
    else ()
        set(ZEEK_BUILTIN_PLUGINS "${ZEEK_BUILTIN_PLUGINS}, ${plugin_name}")
    endif ()
endforeach ()

# ##############################################################################
# Populate the ZEEK_BUILD_INFO for use in src/version.c.in

if (WIN32)
    # Windows installs Python to C:\Python311\python, but doesn't create a version
    # or symlink to python3. Call python with the script directly since the
    # shebang in the script won't work here.
    execute_process(
        COMMAND "python" "${PROJECT_SOURCE_DIR}/ci/collect-repo-info.py" "${ZEEK_INCLUDE_PLUGINS}"
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        OUTPUT_VARIABLE ZEEK_BUILD_INFO
        RESULT_VARIABLE ZEEK_BUILD_INFO_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE)
else ()
    execute_process(
        COMMAND "${PROJECT_SOURCE_DIR}/ci/collect-repo-info.py" "${ZEEK_INCLUDE_PLUGINS}"
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        OUTPUT_VARIABLE ZEEK_BUILD_INFO
        RESULT_VARIABLE ZEEK_BUILD_INFO_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

if (NOT ZEEK_BUILD_INFO_RESULT EQUAL "0")
    message(FATAL_ERROR "Could not collect repository info")
endif ()

# string(JSON ... ) requires CMake 3.19, but then we could do something like:
# string(JSON ZEEK_BUILD_INFO SET "${ZEEK_BUILD_INFO}" compile_options cxx_flags
# "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}")

# ##############################################################################
# Recurse on sub-directories

add_subdirectory(src)
add_subdirectory(scripts)
add_subdirectory(man)
add_subdirectory(testing)

if (NOT DISABLE_SPICY)
    zeek_add_dependencies(spicyz)
endif ()

include(CheckOptionalBuildSources)

checkoptionalbuildsources(auxil/btest BTest INSTALL_BTEST)
checkoptionalbuildsources(auxil/package-manager ZKG INSTALL_ZKG)
checkoptionalbuildsources(auxil/zeekctl ZeekControl INSTALL_ZEEKCTL)
checkoptionalbuildsources(auxil/zeek-aux Zeek-Aux INSTALL_AUX_TOOLS)
checkoptionalbuildsources(auxil/zeek-archiver ZeekArchiver INSTALL_ZEEK_ARCHIVER)
checkoptionalbuildsources(auxil/zeek-client ZeekClient INSTALL_ZEEK_CLIENT)

# Generate Spicy helper scripts referenced in e.g., `zeek-path-dev.*`. These
# set Spicy-side environment variables to run it out of the build directory.
configure_file(${CMAKE_SOURCE_DIR}/cmake_templates/spicy-path.in ${CMAKE_BINARY_DIR}/spicy-path
               @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/cmake_templates/hilti-cxx-include-dirs.in
               ${CMAKE_BINARY_DIR}/hilti-cxx-include-dirs @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_templates/zeek-version.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-version.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-version.h DESTINATION include/zeek)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_templates/zeek-config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h DESTINATION include/zeek)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_templates/zeek-config-paths.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config-paths.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-config-paths.h DESTINATION include/zeek)

# ##############################################################################
# Packaging Setup

if (INSTALL_ZEEKCTL OR INSTALL_ZKG OR INSTALL_ZEEK_CLIENT)
    # CPack RPM Generator may not automatically detect this
    set(CPACK_RPM_PACKAGE_REQUIRES "python >= ${ZEEK_PYTHON_MIN}")
endif ()

# If this CMake project is a sub-project of another, we will not configure the
# generic packaging because CPack will fail in the case that the parent project
# has already configured packaging
if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    include(ConfigurePackaging)
    ConfigurePackaging(${ZEEK_VERSION_FULL})
endif ()

# Refers back to the "distribution prefix". This is the source tree when
# referring to Zeek from the build directory and the "share" directory under the
# install preifx otherwise.
set(ZEEK_DIST_PREFIX $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
                     $<INSTALL_INTERFACE:${CMAKE_INSTALL_DATAROOTDIR}/foo/bar>)

# Generate extra config file for the dynamic plugins.
configure_file(src/ZeekPluginConfig.cmake.in ZeekPluginConfig.cmake @ONLY)

# Write the CMake package and version files.
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ZeekConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfig.cmake" INSTALL_DESTINATION "${ZEEK_CMAKE_CONFIG_DIR}")
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/ZeekConfigVersion.cmake"
                                 VERSION ${ZEEK_VERSION_NUMBER} COMPATIBILITY ExactVersion)

# Write the CMake targets file.
export(EXPORT ZeekTargets FILE ZeekTargets.cmake NAMESPACE Zeek::)

# Write the bootstrap file for dynamic plugins. Needed by ZeekPlugin.cmake.
configure_file(src/ZeekPluginBootstrap.cmake.in ZeekPluginBootstrap.cmake @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ZeekPluginBootstrap.cmake"
        DESTINATION "${ZEEK_CMAKE_CONFIG_DIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfigVersion.cmake"
        DESTINATION "${ZEEK_CMAKE_CONFIG_DIR}")

install(EXPORT ZeekTargets DESTINATION "${ZEEK_CMAKE_CONFIG_DIR}" NAMESPACE Zeek::)

# ##############################################################################
# Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

if (INSTALL_BTEST_PCAPS)
    set(_install_btest_tools_msg "all")
else ()
    set(_install_btest_tools_msg "no pcaps")
endif ()

set(_binpac_exe_path "included")
if (BINPAC_EXE_PATH)
    set(_binpac_exe_path ${BINPAC_EXE_PATH})
endif ()

set(_gen_zam_exe_path "included")
if (GEN_ZAM_EXE_PATH)
    set(_gen_zam_exe_path ${GEN_ZAM_EXE_PATH})
endif ()

set(_spicy "included")
if (DISABLE_SPICY)
    set(_spicy "disabled")
elseif (SPICY_ROOT_DIR)
    set(_spicy "external (${SPICY_ROOT_DIR})")
endif ()

if (ZEEK_LEGACY_ANALYZERS)
    list(JOIN ZEEK_LEGACY_ANALYZERS ", " _legacy_analyzers)
    set(_legacy_analyzers
        "\n          - Using unmaintained legacy analyzers for: ${_legacy_analyzers}")
endif ()

if (ZEEK_SKIPPED_ANALYZERS)
    list(JOIN ZEEK_SKIPPED_ANALYZERS ", " _skipped_analyzers)
    set(_skipped_analyzers "\n          - Skipping analyzers: ${_skipped_analyzers}")
endif ()

if (ZEEK_LEGACY_ANALYZERS OR ZEEK_SKIPPED_ANALYZERS)
    set(_analyzer_warning
        "\n\n[Warning] Some analyzers are not available due to lack of Spicy support:${_legacy_analyzers}${_skipped_analyzers}"
    )
endif ()

message(
    "\n====================|  Zeek Build Summary  |===================="
    "\n"
    "\nBuild type:        ${CMAKE_BUILD_TYPE}"
    "\nBuild dir:         ${PROJECT_BINARY_DIR}"
    "\n"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nConfig file dir:   ${ZEEK_ETC_INSTALL_DIR}"
    "\nLog dir:           ${ZEEK_LOG_DIR}"
    "\nPlugin dir:        ${ZEEK_PLUGIN_DIR}"
    "\nPython module dir: ${PY_MOD_INSTALL_DIR}"
    "\nScript dir:        ${ZEEK_SCRIPT_INSTALL_PATH}"
    "\nSpool dir:         ${ZEEK_SPOOL_DIR}"
    "\nState dir:         ${ZEEK_STATE_DIR}"
    "\nSpicy modules dir: ${ZEEK_SPICY_MODULE_PATH}"
    "\n"
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
    "\nAF_PACKET:         ${ZEEK_HAVE_AF_PACKET}"
    "\nAux. Tools:        ${INSTALL_AUX_TOOLS}"
    "\nBifCL:             ${_bifcl_exe_path}"
    "\nBinPAC:            ${_binpac_exe_path}"
    "\nBTest:             ${INSTALL_BTEST}"
    "\nBTest tooling:     ${_install_btest_tools_msg}"
    "\nGen-ZAM:           ${_gen_zam_exe_path}"
    "\nJavaScript:        ${ZEEK_HAVE_JAVASCRIPT}"
    "\nSpicy:             ${_spicy}"
    "\nSpicy analyzers:   ${USE_SPICY_ANALYZERS}"
    "\nzeek-client:       ${INSTALL_ZEEK_CLIENT}"
    "\nZeekControl:       ${INSTALL_ZEEKCTL}"
    "\nzkg:               ${INSTALL_ZKG}"
    "\n"
    "\nlibmaxminddb:      ${USE_GEOIP}"
    "\nKerberos:          ${USE_KRB5}"
    "\ngperftools found:  ${HAVE_PERFTOOLS}"
    "\n  - tcmalloc:      ${USE_PERFTOOLS_TCMALLOC}"
    "\n  - debugging:     ${USE_PERFTOOLS_DEBUG}"
    "\njemalloc:          ${ENABLE_JEMALLOC}"
    "\n"
    "\nFuzz Targets:      ${ZEEK_ENABLE_FUZZERS}"
    "\nFuzz Engine:       ${ZEEK_FUZZING_ENGINE}"
    "${_analyzer_warning}"
    "\n"
    "\n================================================================\n")

include(UserChangedWarning)
