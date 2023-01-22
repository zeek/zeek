# When changing the minimum version here, also adapt
# auxil/zeek-aux/plugin-support/skeleton/CMakeLists.txt

cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

if ( WIN32 )
    # Enable usage of CMAKE_MSVC_RUNTIME_LIBRARY variable
    cmake_policy(SET CMP0091 NEW)
endif()

project(Zeek C CXX)

option(ZEEK_STANDALONE "Build Zeek as stand-alone binary?" ON)
option(ENABLE_ZEEK_UNIT_TESTS "Build the C++ (doctest) unit tests?" ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON
    CACHE INTERNAL "Write JSON compile commands database")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

# Variable for referring back to Zeek's top-level source dir. Used for plugins
# to tell them where to find the Zeek headers.
set(ZEEK_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# Our C++17 base target for propagating compiler and linker flags.
add_library(zeek_internal INTERFACE)
target_compile_features(zeek_internal INTERFACE cxx_std_17)
add_library(Zeek::Internal ALIAS zeek_internal)
set_target_properties(zeek_internal PROPERTIES EXPORT_NAME Internal)
install(TARGETS zeek_internal EXPORT ZeekTargets)

# Convenience functions for modifying the base target.
function(add_zeek_internal_property name)
    set_property(TARGET zeek_internal PROPERTY ${name} ${ARGN})
endfunction()

function(add_zeek_internal_compile_options)
    target_compile_options(zeek_internal INTERFACE ${ARGN})
endfunction()

function(add_zeek_internal_compile_definitions)
    target_compile_definitions(zeek_internal INTERFACE ${ARGN})
endfunction()

function(add_zeek_internal_link_options)
    target_link_options(zeek_internal INTERFACE ${ARGN})
endfunction()

function(add_zeek_internal_sources)
    target_link_options(zeek_internal INTERFACE ${ARGN})
endfunction()

# Interface library for propagating extra flags and include paths to dynamically
# loaded plugins.
add_library(zeek_dynamic_plugin_base INTERFACE)
target_link_libraries(zeek_dynamic_plugin_base
    INTERFACE
        $<BUILD_INTERFACE:zeek_internal>)
target_include_directories(zeek_dynamic_plugin_base
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
add_library(Zeek::DynamicPluginBase ALIAS zeek_dynamic_plugin_base)
set_target_properties(
  zeek_dynamic_plugin_base PROPERTIES
  EXPORT_NAME DynamicPluginBase)
install(TARGETS zeek_dynamic_plugin_base EXPORT ZeekTargets)

# Tell dynamic plugins where to find scripts such as
# zeek-plugin-create-package.sh.
set(ZEEK_PLUGIN_SCRIPTS_PATH "${PROJECT_SOURCE_DIR}/cmake")

# On macOS, we need to tell the linker that the modules are allowed to have
# undefined symbols.
if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    target_link_options(
        zeek_dynamic_plugin_base
        INTERFACE
            -undefined
            dynamic_lookup
            -Wl,-bind_at_load)
endif ()

function(add_zeek_dynamic_plugin_build_interface_include_directories)
    foreach ( path ${ARGV} )
        target_include_directories(
            zeek_dynamic_plugin_base
            INTERFACE
                $<BUILD_INTERFACE:${path}>
        )
    endforeach ()
endfunction()

add_zeek_dynamic_plugin_build_interface_include_directories(
    ${PROJECT_SOURCE_DIR}/src/include
    ${PROJECT_SOURCE_DIR}/auxil/binpac/lib
    ${PROJECT_SOURCE_DIR}/auxil/broker/include
    ${PROJECT_SOURCE_DIR}/auxil/paraglob/include
    ${PROJECT_SOURCE_DIR}/auxil/rapidjson/include
    ${CMAKE_BINARY_DIR}/src/include
    ${CMAKE_BINARY_DIR}/auxil/binpac/lib
    ${CMAKE_BINARY_DIR}/auxil/broker/include
)

# Target for bundling the creation of auto-generated files.
add_custom_target(zeek_autogen_files)

# Define our main targets and place the output files under src (for historic
# reasons and backwards compatibility).
if (ZEEK_STANDALONE)
    add_executable(zeek_exe)
    target_link_libraries(zeek_exe PRIVATE $<BUILD_INTERFACE:zeek_internal>)
    add_dependencies(zeek_exe zeek_autogen_files)
    set_target_properties(zeek_exe PROPERTIES RUNTIME_OUTPUT_NAME zeek)
    if (NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
        set_target_properties(zeek_exe PROPERTIES RUNTIME_OUTPUT_DIRECTORY src)
    endif()
    install(
        TARGETS zeek_exe
        # EXPORT ZeekTargets
        RUNTIME DESTINATION bin)
        # DESTINATION ${CMAKE_INSTALL_BINDIR})
    # Export symbols from zeek executable for use by plugins
    set_target_properties(zeek_exe PROPERTIES ENABLE_EXPORTS TRUE)
    if ( MSVC )
        set(WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif ()
    # Also build the static library when asked for via Conan.
    if (CONAN_EXPORTED)
        add_library(zeek_lib STATIC)
    endif ()
else ()
    add_library(zeek_lib STATIC)
endif()

if (TARGET zeek_lib)
    target_link_libraries(zeek_lib PRIVATE $<BUILD_INTERFACE:zeek_internal>)
    add_dependencies(zeek_lib zeek_autogen_files)
    set_target_properties(zeek_lib PROPERTIES RUNTIME_OUTPUT_NAME libzeek)
    if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set_target_properties(zeek_lie PROPERTIES LIBRARY_OUTPUT_DIRECTORY src)
    endif()
    install(
        TARGETS zeek_lib
        # EXPORT ZeekTargets
        LIBRARY DESTINATION lib)
endif()

# Convenience function for adding object libraries to the main target(s).
function(zeek_add_obj_lib obj_lib_target)
    foreach (main_target zeek_exe zeek_lib)
        if (TARGET ${main_target})
            target_link_libraries(${main_target} PRIVATE ${obj_lib_target})
        endif ()
    endforeach()
endfunction()

# Convenience function for adding an OBJECT library that feeds directly into the
# main target(s).
#
# Usage:
# zeek_add_subdir_library(
#   <name>
#   SOURCES ...
#   [INCLUDE_DIRS ...]
#   [DEPENDENCIES ...]
#   [INTERNAL_DEPENDENCIES ...]
#   [BIFS ...]
# )
function(zeek_add_subdir_library name)
    # Parse arguments.
    set(fn_varargs INCLUDE_DIRS DEPENDENCIES INTERNAL_DEPENDENCIES SOURCES BIFS)
    cmake_parse_arguments(FN_ARGS "" "" "${fn_varargs}" ${ARGN})
    if (NOT FN_ARGS_SOURCES)
        message(FATAL_ERROR "zeek_add_subdir_library called without any SOURCES")
    endif()

    # Create target and add the sources.
    set(target_name "zeek_${name}_obj")
    add_library(${target_name} OBJECT ${FN_ARGS_SOURCES})
    add_dependencies(${target_name} zeek_autogen_files)
    target_link_libraries(${target_name} PRIVATE $<BUILD_INTERFACE:zeek_internal>)
    add_clang_tidy_files(${FN_ARGS_SOURCES})

    # Take care of compiling BIFs.
    if (FN_ARGS_BIFS)
        foreach ( bif ${FN_ARGS_BIFS} )
              # Generate the target and add the extra dependency.
              bif_target(${bif})
        endforeach ()
    endif()

    # Optionally add include directories and extra dependencies.
    if ( FN_ARGS_INCLUDE_DIRS )
        target_include_directories(
            ${target_name}
            BEFORE
            PRIVATE
              ${FN_ARGS_INCLUDE_DIRS})
    endif ()
    if ( FN_ARGS_DEPENDENCIES )
        target_link_libraries(${target_name} PRIVATE ${FN_ARGS_DEPENDENCIES})
    endif ()
    if ( FN_ARGS_INTERNAL_DEPENDENCIES )
         add_dependencies(${target_name} ${FN_ARGS_INTERNAL_DEPENDENCIES})
    endif ()

    # Feed into the main Zeek target(s).
    zeek_add_obj_lib(${target_name})
endfunction()

# Convenience macros to save ourselves some typing.
macro(zeek_set_default var val)
  if ( NOT ${var} )
    set(${var} ${val})
  endif ()
endmacro()

# Windows: Configure runtime and dependencies
if ( MSVC )
    # Remove existing runtime flags
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO
    )
    foreach(CompilerFlag ${CompilerFlags})
        string(REGEX REPLACE "[/|-]MDd" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]MD" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]MTd" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]MT" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]Zi" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]W3" "" ${CompilerFlag} "${${CompilerFlag}}")
        string(REGEX REPLACE "[/|-]W4" "" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()

    # Set compilation flags for Windows
    add_zeek_internal_compile_options(
        /guard:cf                # required by CheckCFlags
        /Z7                      # required by CheckCFlags
        $<$<CONFIG:Release>:/MT> # force static runtime for release builds
        $<$<CONFIG:Debug>:/MTd>  # force static runtime for debug builds
    )

    add_zeek_internal_link_options(
        /debug:full # required by CheckCFlags
    )

    # Always use static runtime
    add_zeek_internal_compile_options(
        $<CONFIG:Debug>:/MTd;/DDEBUG>
        $<CONFIG:Release>:/MT>
    )
    add_zeek_internal_property(
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
    add_zeek_internal_property(
      MSVC_RUNTIME_LIBRARY_FLAG "MT$<$<CONFIG:Debug>:d>"
    )

    set(OPENSSL_USE_STATIC_LIBS ON)
    set(OPENSSL_MSVC_STATIC_RT ON)

    if ( ZEEK_STANDALONE )
        include(${CMAKE_SOURCE_DIR}/cmake/conan.cmake)
        conan_cmake_autodetect(settings)
        # Install packages from conanfile
        conan_cmake_install(PATH_OR_REFERENCE ${CMAKE_SOURCE_DIR}/ci/windows/conanfile_windows.txt
                            BUILD missing
                            SETTINGS ${settings})
    endif()

    # Set LibPCAP to point to libpcap binaries.
    if ( NOT PCAP_ROOT_DIR )
        find_package(libpcap)
        set(PCAP_ROOT_DIR "${libpcap_LIB_DIRS}/../")
        set(PCAP_INCLUDE_DIR ${libpcap_INCLUDES})
        set(PCAP_LIBRARY ${libpcap_LIBS})
    endif()

    set(LIBPCAP_PCAP_COMPILE_NOPCAP_HAS_ERROR_PARAMETER false)

    # Set ZLib to point at the right variable.
    find_package(ZLIB)
    set(ZLIB_LIBRARY ${ZLIB_LIBRARIES})

    # Set CAres
    find_package(c-ares)
    set(HAVE_CARES true) # Disable FindCAres cmake file
    include_directories(BEFORE ${c-ares_INCLUDE_DIRS})
    set(zeekdeps ${zeekdeps} ${c-ares_LIBRARIES})
    add_definitions(-DCARES_STATICLIB)

    add_subdirectory(auxil/libunistd)
    set(UNISTD_INCLUDES ${CMAKE_SOURCE_DIR}/auxil/libunistd/unistd ${CMAKE_SOURCE_DIR}/auxil/libunistd/regex)
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
else ()
    # Use the GNU path conventions for out install targets.
    include(GNUInstallDirs)

    # Enable more warnings by default.
    add_zeek_internal_compile_options(
        -Wall
        -Wno-unused
        -Wno-register
        -Werror=vla
    )

    # Turn on coverage for debug builds if requested.
    if ( ENABLE_COVERAGE )
        add_zeek_internal_compile_options(
            $<$<CONFIG:Debug>:--coverage>
            $<$<CONFIG:Debug>:-g>
        )
        add_zeek_internal_compile_definitions(
            $<$<CONFIG:Debug>:DEBUG>
            $<$<CONFIG:Debug>:BRO_DEBUG>
        )
    endif ()
endif ()

########################################################################
## Utility function for forcing Zeek to re-run if files change on disk.

function(zeek_watch_files)
    set_property(
            DIRECTORY
            APPEND
            PROPERTY CMAKE_CONFIGURE_DEPENDS ${ARGN}
    )
endfunction()

########################################################################
## Create empty __load__.zeek stubs (override pre-existing ones).

function(zeek_create_load_script_stubs)
    set(file_comment "# Warning, this is an autogenerated file!\n")
    foreach ( fpath ${ARGN} )
        file(WRITE "${CMAKE_BINARY_DIR}/${fpath}" "${file_comment}")
        zeek_watch_files("${CMAKE_BINARY_DIR}/${fpath}")
    endforeach ()
endfunction ()

# Note: these files are filled from BifCl.cmake via `file(APPEND ...)`
zeek_create_load_script_stubs(
    scripts/builtin-plugins/__load__.zeek
    scripts/base/bif/plugins/__load__.zeek
    scripts/base/bif/__load__.zeek
)

########################################################################
## Create empty __all__*.cc stubs (override pre-existing ones).

function(zeek_create_bif_autogen_stubs)
    set(file_comment "// Warning, this is an autogenerated file!\n")
    foreach ( fpath ${ARGN} )
        file(WRITE "${CMAKE_BINARY_DIR}/${fpath}" "${file_comment}")
        zeek_watch_files("${CMAKE_BINARY_DIR}/${fpath}")
    endforeach ()
endfunction ()

# Note: these files are filled from BifCl.cmake via `file(APPEND ...)`.
zeek_create_bif_autogen_stubs(
    src/__all__.bif.cc
    src/__all__.bif.init.cc
    src/__all__.bif.register.cc
)

########################################################################
## Project/Build Configuration

include(cmake/FindClangTidy.cmake)
include(cmake/CheckCompilerArch.cmake)

if ( ZEEK_ENABLE_FUZZERS )
    # Fuzzers use shared lib to save disk space, so need -fPIC on everything
    add_zeek_internal_property(POSITION_INDEPENDENT_CODE ON)
endif ()

if (ENABLE_ZEEK_UNIT_TESTS)
    enable_testing()
    add_zeek_internal_compile_definitions(DOCTEST_CONFIG_SUPER_FAST_ASSERTS)
else ()
    add_zeek_internal_compile_definitions(DOCTEST_CONFIG_DISABLE)
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

# Set the default script installation path if the user did not specify one.
zeek_set_default(ZEEK_SCRIPT_INSTALL_PATH ${ZEEK_ROOT_DIR}/share/zeek)

# Set the default man page installation path if the user did not specify one.
zeek_set_default(ZEEK_MAN_INSTALL_PATH ${ZEEK_ROOT_DIR}/share/man)

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
endif()

set(bro_plugin_install_path "${BRO_PLUGIN_INSTALL_PATH}")
set(cmake_binary_dir "${CMAKE_BINARY_DIR}")
set(cmake_current_binary_dir "${CMAKE_CURRENT_BINARY_DIR}")
set(cmake_install_prefix "${CMAKE_INSTALL_PREFIX}")
set(cmake_source_dir "${CMAKE_SOURCE_DIR}")
set(zeek_script_install_path "${ZEEK_SCRIPT_INSTALL_PATH}")
if ( MSVC )
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" bro_plugin_install_path "${bro_plugin_install_path}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_binary_dir "${cmake_binary_dir}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_current_binary_dir "${cmake_current_binary_dir}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_install_prefix "${cmake_install_prefix}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" cmake_source_dir "${cmake_source_dir}")
    string(REGEX REPLACE "^([A-Za-z]):/(.*)" "/\\1/\\2" zeek_script_install_path "${zeek_script_install_path}")
endif ()

zeek_set_default(ZEEK_ETC_INSTALL_DIR ${ZEEK_ROOT_DIR}/etc)

zeek_set_default(ZEEK_STATE_DIR ${ZEEK_ROOT_DIR}/var/lib)

zeek_set_default(ZEEK_SPOOL_DIR ${ZEEK_ROOT_DIR}/spool)

zeek_set_default(ZEEK_LOG_DIR ${ZEEK_ROOT_DIR}/logs)

if ( NOT MSVC )
    set(HAVE_SUPERVISOR ON)
endif ()

install(DIRECTORY DESTINATION ${ZEEK_ETC_INSTALL_DIR})
install(DIRECTORY DESTINATION ${ZEEK_STATE_DIR})
install(DIRECTORY DESTINATION ${ZEEK_SPOOL_DIR})
install(DIRECTORY DESTINATION ${ZEEK_LOG_DIR})

configure_file(zeek-path-dev.in ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.sh
     "export ZEEKPATH=`${cmake_binary_dir}/zeek-path-dev`\n"
     "export ZEEK_PLUGIN_PATH=\"${cmake_binary_dir}/src\":$\{ZEEK_PLUGIN_PATH\}\n"
     "export PATH=\"${cmake_binary_dir}\":\"${cmake_binary_dir}/src\":\"${cmake_binary_dir}/auxil/spicy/spicy/bin\":\"${cmake_binary_dir}/src/builtin-plugins/spicy-plugin/bin\":$\{PATH\}\n"
     "export SPICY_PATH=`${cmake_binary_dir}/spicy-path`\n"
     "export HILTI_CXX_INCLUDE_DIRS=`${cmake_binary_dir}/hilti-cxx-include-dirs`\n")

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/zeek-path-dev.csh
     "setenv ZEEKPATH `${cmake_binary_dir}/zeek-path-dev`\n"
     "setenv ZEEK_PLUGIN_PATH \"${cmake_binary_dir}/src\":$\{ZEEK_PLUGIN_PATH\}\n"
     "setenv PATH \"${cmake_binary_dir}\":\"${cmake_binary_dir}/src\":\"${cmake_binary_dir}/auxil/spicy/spicy/bin\":\"${cmake_binary_dir}/src/builtin-plugins/spicy-plugin/bin\":$\{PATH\}\n"
     "setenv SPICY_PATH \"`${cmake_binary_dir}/spicy-path`\"\n"
     "setenv HILTI_CXX_INCLUDE_DIRS \"`${cmake_binary_dir}/hilti-cxx-include-dirs`\"\n")

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)
execute_process(COMMAND grep "^constexpr int PLUGIN_API_VERSION"
                INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/plugin/Plugin.h
                OUTPUT_VARIABLE API_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE)

string(REGEX MATCH "^constexpr int PLUGIN_API_VERSION = ([0-9]+);" API_VERSION "${API_VERSION}")
set(API_VERSION "${CMAKE_MATCH_1}")

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

if ( ENABLE_DEBUG )
    set(VERSION_C_IDENT "${VERSION_C_IDENT}_debug")
    add_zeek_internal_compile_definitions(DEBUG)
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
                list(APPEND _check_list "null")
                # list(APPEND _check_list "nullability-arg") # Not normally part of "undefined"
                # list(APPEND _check_list "nullability-assign") # Not normally part of "undefined"
                # list(APPEND _check_list "nullability-return") # Not normally part of "undefined"
                # list(APPEND _check_list "objc-cast") # Not truly UB
                # list(APPEND _check_list "pointer-overflow") # Not implemented in older GCCs
                list(APPEND _check_list "return")
                list(APPEND _check_list "returns-nonnull-attribute")
                list(APPEND _check_list "shift")
                # list(APPEND _check_list "unsigned-shift-base") # Not implemented by GCC
                list(APPEND _check_list "signed-integer-overflow")
                list(APPEND _check_list "unreachable")
                # list(APPEND _check_list "unsigned-integer-overflow") # Not truly UB
                list(APPEND _check_list "vla-bound")
                list(APPEND _check_list "vptr")

                # Clang complains if this one is defined and the optimizer is set to -O0. We
                # only set that optimization level if NO_OPTIMIZATIONS is passed, so disable
                # the option if that's set.
                if ( NOT DEFINED ENV{NO_OPTIMIZATIONS} )
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

    # The linker command used by check_cxx_compiler_flag requires you to also pass the sanitizer to
    # it or it fails. The best way to do this is to set CMAKE_REQUIRED_LINK_OPTIONS, but save off a
    # copy of it so it can be reset back to what it was previously afterwards.
    set(_temp_link_options ${CMAKE_REQUIRED_LINK_OPTIONS})
    list(APPEND CMAKE_REQUIRED_LINK_OPTIONS ${_sanitizer_flags})
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(${_sanitizer_flags} COMPILER_SUPPORTS_SANITIZERS)
    if ( NOT COMPILER_SUPPORTS_SANITIZERS )
      message(FATAL_ERROR "Invalid sanitizer compiler flags: ${_sanitizer_flags}")
    endif()
    set(CMAKE_REQUIRED_LINK_OPTIONS ${_temp_link_options})

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
if ( NOT MSVC )
    FindRequiredPackage(BIND)
endif ()
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
    if ( MSVC )
        set(BUILD_STATIC_BINPAC true)
    endif()

    if ( BUILD_STATIC_BINPAC )
      set(ENABLE_STATIC_ONLY true)
    endif()

    add_subdirectory(auxil/binpac)
    set(ENABLE_STATIC_ONLY ${ENABLE_STATIC_ONLY_SAVED})

    # FIXME: avoid hard-coding a path for multi-config generator support.
    # See the TODO in ZeekPluginConfig.cmake.in.
    set(BINPAC_EXE_PATH "${CMAKE_BINARY_DIR}/auxil/binpac/src/binpac${CMAKE_EXECUTABLE_SUFFIX}")
else ()
    FindRequiredPackage(BinPAC)
endif ()

# Add an alias
add_executable(Zeek::BinPAC ALIAS binpac)

if ( NOT BIFCL_EXE_PATH )
    add_subdirectory(auxil/bifcl)
    add_executable(Zeek::BifCl ALIAS bifcl)
    # FIXME: avoid hard-coding a path for multi-config generator support.
    # See the TODO in ZeekPluginConfig.cmake.in.
    set(BIFCL_EXE_PATH "${CMAKE_BINARY_DIR}/auxil/bifcl/bifcl${CMAKE_EXECUTABLE_SUFFIX}")
else ()
    add_executable(Zeek::BifCl IMPORTED)
    set_property(TARGET Zeek::BifCl PROPERTY
                 IMPORTED_LOCATION "${BIFCL_EXE_PATH}")
endif ()

if ( NOT GEN_ZAM_EXE_PATH )
    add_subdirectory(auxil/gen-zam)
endif ()

if (ENABLE_JEMALLOC)
    if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        if (DEFINED JEMALLOC_ROOT_DIR)
            # Look for jemalloc at a specific path
            find_package(JeMalloc)
        else()
            # jemalloc is in the base system
            set(JEMALLOC_FOUND true)
        endif()
    else()
        find_package(JeMalloc)
    endif()

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

add_subdirectory(auxil/paraglob)
if ( MSVC )
    cmake_policy(SET CMP0079 NEW)
    target_link_libraries(paraglob shlwapi)
    set(BROKER_DISABLE_TOOLS true)
endif ()
set(zeekdeps ${zeekdeps} paraglob)

if ( Broker_ROOT )
  find_package(Broker REQUIRED PATHS "${Broker_ROOT}")
  set(zeekdeps ${zeekdeps} ${BROKER_LIBRARY})
  set(broker_includes ${BROKER_INCLUDE_DIR})
  set(ZEEK_HAS_EXTERNAL_BROKER ON)
elseif ( BROKER_ROOT_DIR )
  find_package(Broker REQUIRED PATHS "${BROKER_ROOT_DIR}")
  set(zeekdeps ${zeekdeps} ${BROKER_LIBRARY})
  set(broker_includes ${BROKER_INCLUDE_DIR})
  set(ZEEK_HAS_EXTERNAL_BROKER ON)
else ()
  if ( ZEEK_SANITIZERS )
    set(BROKER_SANITIZERS ${ZEEK_SANITIZERS})
  endif ()

  set(ENABLE_STATIC_ONLY_SAVED ${ENABLE_STATIC_ONLY})
  if ( MSVC )
    set(BUILD_STATIC_BROKER true)
  endif()

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

if ( NOT DISABLE_SPICY )
    set(USE_SPICY_ANALYZERS yes)

    if ( NOT SPICY_ROOT_DIR )
        set(HAVE_SPICY yes) # evaluated by Spicy plugin build

        add_subdirectory(auxil/spicy)

        # Set variables used by the spicy-plugin build since we are building Spicy
        # as part of Zeek so spicy-plugin cannot use `spicy-config` at configure
        # time to set these.
        set(SPICY_CONFIG "<builtin>")
        set(SPICY_HAVE_TOOLCHAIN "YES")
        set(SPICY_INCLUDE_DIRS_RUNTIME
            ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy/hilti/runtime/include
            ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy/spicy/runtime/include
            ${PROJECT_BINARY_DIR}/auxil/spicy/spicy/include)
        set(SPICY_INCLUDE_DIRS_TOOLCHAIN
            ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy/hilti/toolchain/include
            ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy/spicy/toolchain/include)
        set(SPICY_LIBRARY spicy)
        set(HILTI_LIBRARY_RT hilti-rt)
        set(HILTI_LIBRARY_RT_DEBUG hilti-rt-debug)
        set(SPICY_LIBRARY_RT spicy-rt)
        set(SPICY_LIBRARY_RT_DEBUG spicy-rt-debug)

        # Needed only for logging from CMake configure phase.
        get_directory_property(
            SPICY_VERSION
            DIRECTORY ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy
            DEFINITION SPICY_VERSION)
        get_directory_property(
            SPICY_VERSION_NUMBER
            DIRECTORY ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy
            DEFINITION SPICY_VERSION_NUMBER)
        get_directory_property(
            SPICY_PREFIX
            DIRECTORY ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy
            DEFINITION CMAKE_INSTALL_PREFIX)
        get_directory_property(
            SPICY_BUILD_MODE
            DIRECTORY ${PROJECT_SOURCE_DIR}/auxil/spicy/spicy
            DEFINITION CMAKE_BUILD_TYPE)
        set(SPICYC "<bundled>")
    endif ()

    if ( NOT SPICY_PLUGIN_PATH )
        set(_spicy_plugin "included")
        set(SPICY_PLUGIN_PATH ${CMAKE_SOURCE_DIR}/auxil/spicy-plugin)
    endif ()

    set(SPICY_PLUGIN_BINARY_PATH ${CMAKE_BINARY_DIR}/src/builtin-plugins/spicy-plugin)
    string(APPEND ZEEK_INCLUDE_PLUGINS ";${SPICY_PLUGIN_PATH}")
else ()
    set(HAVE_SPICY no) # evaluated by Spicy plugin build
    set(USE_SPICY_ANALYZERS no)
endif ()

set(USE_SPICY_ANALYZERS "${USE_SPICY_ANALYZERS}" CACHE BOOL "Use built-in Spicy analyzers")
include(BuiltInSpicyAnalyzer)

include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR}
                    ${BinPAC_INCLUDE_DIR}
                    ${ZLIB_INCLUDE_DIR}
                    ${JEMALLOC_INCLUDE_DIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/auxil/rapidjson/include/rapidjson
        DESTINATION include/zeek/3rdparty/rapidjson/include)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/auxil/filesystem/include/ghc
        DESTINATION include/zeek/3rdparty/)

# Create 3rdparty/ghc within the build directory so that the include for
# "zeek/3rdparty/ghc/filesystem.hpp" works within the build tree.
execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory
                "${CMAKE_CURRENT_BINARY_DIR}/3rdparty/")
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
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
    set(ZEEK_HAS_EXTERNAL_LIBFTS ON)
endif ()

# Any headers that are possibly bundled in the Zeek source-tree and that are supposed
# to have priority over any preexisting/system-wide headers need to appear early in
# compiler search path.
include_directories(BEFORE ${broker_includes})
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
include(FindCAres)
include_directories(BEFORE "auxil/out_ptr/include")

if ( (OPENSSL_VERSION VERSION_EQUAL "1.1.0") OR (OPENSSL_VERSION VERSION_GREATER "1.1.0") )
  set(ZEEK_HAVE_OPENSSL_1_1 true CACHE INTERNAL "" FORCE)
endif()
if ( (OPENSSL_VERSION VERSION_EQUAL "3.0.0") OR (OPENSSL_VERSION VERSION_GREATER "3.0.0") )
  set(ZEEK_HAVE_OPENSSL_3_0 true CACHE INTERNAL "" FORCE)
endif()

# Tell the plugin code that we're building as part of the main tree.
set(ZEEK_PLUGIN_INTERNAL_BUILD true CACHE INTERNAL "" FORCE)

if ( ${CMAKE_SYSTEM_NAME} MATCHES Linux )
    if ( NOT DISABLE_AF_PACKET )
        if ( NOT AF_PACKET_PLUGIN_PATH )
            set(AF_PACKET_PLUGIN_PATH ${CMAKE_SOURCE_DIR}/auxil/zeek-af_packet-plugin)
        endif ()

        string(APPEND ZEEK_INCLUDE_PLUGINS ";${AF_PACKET_PLUGIN_PATH}")
    endif ()
endif ()

set(DEFAULT_ZEEKPATH_PATHS . ${ZEEK_SCRIPT_INSTALL_PATH} ${ZEEK_SCRIPT_INSTALL_PATH}/policy ${ZEEK_SCRIPT_INSTALL_PATH}/site ${ZEEK_SCRIPT_INSTALL_PATH}/builtin-plugins)
if ( MSVC )
    list(JOIN DEFAULT_ZEEKPATH_PATHS ";" DEFAULT_ZEEKPATH)
else ()
    list(JOIN DEFAULT_ZEEKPATH_PATHS ":" DEFAULT_ZEEKPATH)
endif ()

if ( NOT BINARY_PACKAGING_MODE )
    set(ZEEK_DIST ${PROJECT_SOURCE_DIR})
endif ()

string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/zeek-config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h)
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeek-config.h DESTINATION include/zeek)
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                "."
                "${CMAKE_CURRENT_BINARY_DIR}/zeek")

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

if ( NOT MSVC )
  # Install wrapper script for Bro-to-Zeek renaming.
  include(InstallShellScript)
  include(InstallSymlink)
endif ()

########################################################################
## zkg configuration

if ( INSTALL_ZKG )
    # An etc/zkg directory for zkg's config file simplifies zkg's
    # config file code.
    set(ZEEK_ZKG_CONFIG_DIR "${ZEEK_ETC_INSTALL_DIR}/zkg")
    set(ZEEK_ZKG_STATE_DIR "${ZEEK_STATE_DIR}/zkg")

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

if ( NOT DISABLE_SPICY )
    # The `zeek` binary (or `libzeek`) implicitly depends on the driver object
    # file built as part of `spicy`; make that dependency explicit.
    if ( TARGET zeek_exe )
        set(spicyZeekTarget zeek_exe)
    elseif ( TARGET zeek_lib )
        set(spicyZeekTarget zeek_lib)
    endif ()
    add_dependencies(${spicyZeekTarget} spicyz)

    if ( NOT SPICY_ROOT_DIR )
        list(APPEND _spicy_rt_libs spicy-rt hilti-rt)

        # Use the debug runtime libraries if we are building a debug Zeek.
        if ( SPICY_BUILD_MODE STREQUAL "Debug" )
            list(TRANSFORM _spicy_rt_libs APPEND "-debug")
        endif ()

        # If we build spicy-plugin into Zeek we also need to build the Spicy
        # runtime dependencies into Zeek. Since no matter how Spicy itself was
        # linked this is always a static library, link the object files so we
        # get all symbols and can resolve all potential dependencies of
        # HLTO files at runtime.
        #
        # TODO(bbannier): Conceptually cleaner would be linking the runtime
        # objects into spicy-plugin and then inherit that up to zeek, but it
        # seems this does not work reliable (due incomplete support for object
        # libraries in CMake?).
        list(TRANSFORM _spicy_rt_libs APPEND "-objects")
        target_link_libraries(${spicyZeekTarget} PUBLIC ${_spicy_rt_libs})

        # Make sure we build targets of spicy-plugin after the `spicy` target.
        #add_dependencies(plugin-Zeek-Spicy spicy)
        #add_dependencies(spicyz spicy)

        # Also install spicy-plugin's CMake files into Zeek's global `cmake/` folder.
        #
        # NOTE: We do not install spicy-plugin's `FindZeek.cmake` since another
        # version of this file is already provided by Zeek.
        install(FILES auxil/spicy-plugin/cmake/ZeekSpicyAnalyzerSupport.cmake
                      auxil/spicy-plugin/cmake/FindSpicy.cmake
                DESTINATION share/zeek/cmake)
    endif ()
endif ()

# Always generate helper scripts referenced in e.g., `zeek-path-dev.*` so the
# scripts work in any build configuration. If we do not include Spicy these
# files have no actual effect.
#
# Spicy JIT relies on the path of the current executable to figure out
# whether it is run from a build or an install tree. This assumption
# gets broken for e.g., `spicyz` when running from the build tree
# (probably fixable), and also when JIT'ing directly from a `zeek`
# invocation (much harder to fix). Instead we generate shell
# definitions to support running and using Spicy or spicy-plugin
# functionality in the build tree, including JIT'ing directly from
# Zeek.
configure_file(${CMAKE_SOURCE_DIR}/auxil/spicy/spicy-path.in ${CMAKE_BINARY_DIR}/spicy-path @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/auxil/spicy/hilti-cxx-include-dirs.in ${CMAKE_BINARY_DIR}/hilti-cxx-include-dirs @ONLY)

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

# List for assembling all dependencies for the Zeek library target. Also needed
# when building dynamic plugins.
set(ZEEK_INSTALL_DEPENDENCIES LibMMDB)

macro(add_install_dependency var dep)
    if (${var})
        list(APPEND ZEEK_INSTALL_DEPENDENCIES ${dep})
    endif ()
endmacro()

add_install_dependency(ENABLE_JEMALLOC JeMalloc)
add_install_dependency(USE_KRB5 LibKrb5)
add_install_dependency(ENABLE_PERFTOOLS GooglePerftools)
add_install_dependency(ZEEK_HAS_EXTERNAL_LIBFTS FTS)
add_install_dependency(BROKER_USE_EXTERNAL_CAF CAF)
add_install_dependency(ZEEK_HAS_EXTERNAL_BROKER Broker)

# Refers back to the "distribution prefix". This is the source tree when
# referring to Zeek from the build directory and the "share" directory under the
# install preifx otherwise.
set(ZEEK_DIST_PREFIX
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_DATAROOTDIR}/foo/bar>)

# Generate extra config file for the dynamic plugins.
configure_file(src/ZeekPluginConfig.cmake.in ZeekPluginConfig.cmake @ONLY)

# Write the CMake package and version files.
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/ZeekConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Zeek")
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfigVersion.cmake"
  VERSION ${ZEEK_VERSION_NUMBER}
  COMPATIBILITY ExactVersion)

# Install all the things.
export(EXPORT ZeekTargets FILE ZeekTargets.cmake NAMESPACE Zeek::)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ZeekConfigVersion.cmake"
  DESTINATION
    "${CMAKE_INSTALL_LIBDIR}/cmake/Zeek")
install(
  EXPORT ZeekTargets
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Zeek"
  NAMESPACE Zeek::)

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

set(_bifcl_exe_path "included")
if ( BIFCL_EXE_PATH )
    set(_bifcl_exe_path ${BIFCL_EXE_PATH})
endif ()

set(_binpac_exe_path "included")
if ( BINPAC_EXE_PATH )
    set(_binpac_exe_path ${BINPAC_EXE_PATH})
endif ()

set(_gen_zam_exe_path "included")
if ( GEN_ZAM_EXE_PATH )
    set(_gen_zam_exe_path ${GEN_ZAM_EXE_PATH})
endif ()

set(_spicy "included")
if ( DISABLE_SPICY )
    set(_spicy "disabled")
elseif ( SPICY_ROOT_DIR )
    set(_spicy "external (${SPICY_ROOT_DIR})")
endif ()

if ( DISABLE_SPICY )
    set(_spicy_plugin "disabled")
elseif ( "${_spicy_plugin}" STREQUAL "" )
    set(_spicy_plugin "external (${SPICY_PLUGIN_PATH})")
endif ()

if ( ZEEK_LEGACY_ANALYZERS )
    list(JOIN ZEEK_LEGACY_ANALYZERS ", " _legacy_analyzers)
    set(_legacy_analyzers  "\n          - Using unmaintained legacy analyzers for: ${_legacy_analyzers}")
endif ()

if ( ZEEK_SKIPPED_ANALYZERS )
    list(JOIN ZEEK_SKIPPED_ANALYZERS ", " _skipped_analyzers)
    set(_skipped_analyzers "\n          - Skipping analyzers: ${_skipped_analyzers}")
endif ()

if ( ZEEK_LEGACY_ANALYZERS OR ZEEK_SKIPPED_ANALYZERS )
    set(_analyzer_warning "\n\n[Warning] Some analyzers are not available due to lack of built-in Spicy support:${_legacy_analyzers}${_skipped_analyzers}")
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
    "\nPlugin dir:        ${BRO_PLUGIN_INSTALL_PATH}"
    "\nPython module dir: ${PY_MOD_INSTALL_DIR}"
    "\nScript dir:        ${ZEEK_SCRIPT_INSTALL_PATH}"
    "\nSpool dir:         ${ZEEK_SPOOL_DIR}"
    "\nState dir:         ${ZEEK_STATE_DIR}"
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
    "\nzeek-client:       ${INSTALL_ZEEK_CLIENT}"
    "\nZeekControl:       ${INSTALL_ZEEKCTL}"
    "\nAux. Tools:        ${INSTALL_AUX_TOOLS}"
    "\nBifCL:             ${_bifcl_exe_path}"
    "\nBinPAC:            ${_binpac_exe_path}"
    "\nBTest:             ${INSTALL_BTEST}"
    "\nBTest tooling:     ${_install_btest_tools_msg}"
    "\nGen-ZAM:           ${_gen_zam_exe_path}"
    "\nzkg:               ${INSTALL_ZKG}"
    "\nSpicy:             ${_spicy}"
    "\nSpicy plugin:      ${_spicy_plugin}"
    "\nSpicy analyzers:   ${USE_SPICY_ANALYZERS}"
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
    "${_analyzer_warning}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
