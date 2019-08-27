include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

# This collects generated bif and pac files from subdirectories.
set(bro_ALL_GENERATED_OUTPUTS  CACHE INTERNAL "automatically generated files" FORCE)

# This collects bif inputs that we'll load automatically.
set(bro_AUTO_BIFS     CACHE INTERNAL "BIFs for automatic inclusion" FORCE)
set(bro_REGISTER_BIFS CACHE INTERNAL "BIFs for automatic registering" FORCE)

set(bro_BASE_BIF_SCRIPTS CACHE INTERNAL "Zeek script stubs for BIFs in base distribution of Zeek" FORCE)
set(bro_PLUGIN_BIF_SCRIPTS CACHE INTERNAL "Zeek script stubs for BIFs in Zeek plugins" FORCE)

# If TRUE, use CMake's object libraries for sub-directories instead of
# static libraries. This requires CMake >= 2.8.8.
set(bro_HAVE_OBJECT_LIBRARIES FALSE)

configure_file(version.c.in ${CMAKE_CURRENT_BINARY_DIR}/version.c)
configure_file(util-config.h.in ${CMAKE_CURRENT_BINARY_DIR}/util-config.h)

# This creates a custom command to transform a bison output file (inFile)
# into outFile in order to avoid symbol conflicts:
# - replaces instances of 'yylex' in inFile with yylexPrefix
# - replaces instances of 'yy' in inFile with yyPrefix
# - deletes instances of 'extern char.*getenv' in inFile
# - writes results to outFile and adds it to list TRANSFORMED_BISON_OUTPUTS
macro(REPLACE_YY_PREFIX_TARGET inFile outFile yylexPrefix yyPrefix)
    set(args "'/extern char.*getenv/d")
    set(args "${args}\;s/yylex/${yylexPrefix}lex/")
    set(args "${args}\;s/yy/${yyPrefix}/g'" < ${inFile} > ${outFile})
    add_custom_command(OUTPUT ${outFile}
                       COMMAND ${SED_EXE}
                       ARGS ${args}
                       DEPENDS ${inFile}
                       COMMENT "[sed] replacing stuff in ${inFile}"
    )
    list(APPEND TRANSFORMED_BISON_OUTPUTS ${outFile})
endmacro(REPLACE_YY_PREFIX_TARGET)

########################################################################
## Create targets to generate parser and scanner code

set(BISON_FLAGS "--debug")

# BIF parser/scanner
bison_target(BIFParser builtin-func.y
             ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.h
             #VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
flex_target(BIFScanner builtin-func.l ${CMAKE_CURRENT_BINARY_DIR}/bif_lex.cc)
add_flex_bison_dependency(BIFScanner BIFParser)
set_property(SOURCE bif_lex.cc APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-sign-compare")

# Rule parser/scanner
bison_target(RuleParser rule-parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/rup.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/rup.h
             #VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/rule_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rup.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/rule-parse.cc
                         rules_ rules_)
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rup.h
                         ${CMAKE_CURRENT_BINARY_DIR}/rule-parse.h
                         rules_ rules_)
flex_target(RuleScanner rule-scan.l ${CMAKE_CURRENT_BINARY_DIR}/rule-scan.cc
            COMPILE_FLAGS "-Prules_")
set_property(SOURCE rule-scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-sign-compare")

# RE parser/scanner
bison_target(REParser re-parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/rep.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/re-parse.h
             #VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/re_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rep.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/re-parse.cc
                         re_ RE_)
flex_target(REScanner re-scan.l ${CMAKE_CURRENT_BINARY_DIR}/re-scan.cc
            COMPILE_FLAGS "-Pre_")
add_flex_bison_dependency(REScanner REParser)
set_property(SOURCE re-scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-sign-compare")

# Parser/Scanner
bison_target(Parser parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/p.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/broparse.h
             #VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/p.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/parse.cc
                         bro yy)
flex_target(Scanner scan.l ${CMAKE_CURRENT_BINARY_DIR}/scan.cc
            COMPILE_FLAGS "-Pbro")
set_property(SOURCE scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-sign-compare")

########################################################################
## bifcl-dependent targets

include(BifCl)

set(BIF_SRCS
    zeek.bif
    stats.bif
    event.bif
    const.bif
    types.bif
    strings.bif
    reporter.bif
    option.bif
)

foreach (bift ${BIF_SRCS})
    bif_target(${bift} "standard")
endforeach ()

########################################################################
## BinPAC-dependent targets

include(BinPAC)

set(BINPAC_AUXSRC
    ${CMAKE_SOURCE_DIR}/src/binpac.pac
    ${CMAKE_SOURCE_DIR}/src/bro.pac
    ${CMAKE_SOURCE_DIR}/src/binpac_bro.h
)

binpac_target(binpac-lib.pac)
list(APPEND BINPAC_OUTPUTS "${BINPAC_OUTPUT_CC}")

binpac_target(binpac_bro-lib.pac)
list(APPEND BINPAC_OUTPUTS "${BINPAC_OUTPUT_CC}")

########################################################################
## libuv for the event loop
##
## The majority of this was taken from the configuration for CAF in the
## broker module.

if ( LIBUV_ROOT_DIR )
  set(static_ext "${CMAKE_STATIC_LIBRARY_SUFFIX}")

  find_path(LIBUV_ROOT_DIR
    NAMES "include/uv.h")

  find_library(LIBUV_LIBRARIES
    NAMES libuv.a
    HINTS ${LIBUV_ROOT_DIR}/lib)
  
  find_path(LIBUV_INCLUDE_DIRS
    NAMES uv.h
    HINTS ${LIBUV_ROOT_DIR}/include)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LIBUV DEFAULT_MSG
    LIBUV_LIBRARIES
    LIBUV_INCLUDE_DIRS
    )
  
  mark_as_advanced(
    LIBUV_ROOT_DIR
    LIBUV_LIBRARIES
    LIBUV_INCLUDE_DIRS
    )

else ()

  include(ExternalProject)
  set(uv_src     "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/libuv")
  set(uv_ep      "${CMAKE_CURRENT_BINARY_DIR}/libuv-ep")
  set(uv_build   "${CMAKE_CURRENT_BINARY_DIR}/libuv-build")
  set(uv_dir     "${uv_src}")
  set(uv_install "${CMAKE_INSTALL_PREFIX}")
  set(static_ext "${CMAKE_STATIC_LIBRARY_SUFFIX}")

  if ( ${CMAKE_VERSION} VERSION_LESS "3.2.0" )
    # Build byproducts is just required by the Ninja generator
    # though it's not available before CMake 3.2 ...
    if ( ${CMAKE_GENERATOR} STREQUAL Ninja )
      message(FATAL_ERROR "Ninja generator requires CMake >= 3.2")
    endif ()

    set(build_byproducts_arg)
  else ()
    set(build_byproducts_arg BUILD_BYPRODUCTS
      ${uv_build}/libuv_a${static_ext}
      )
  endif ()

  message("${build_byproducts_arg}")

  ExternalProject_Add(project_uv
    PREFIX            "${uv_ep}"
    BINARY_DIR        "${uv_build}"
    DOWNLOAD_COMMAND  ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    ${build_byproducts_arg}
  )

  if ( ${CMAKE_VERSION} VERSION_LESS "3.4.0" )
    set(use_terminal_arg)
  else ()
    set(use_terminal_arg USES_TERMINAL 1)
  endif ()

  ExternalProject_Add_Step(project_uv project_uv_build_step
    COMMAND ${CMAKE_MAKE_PROGRAM}
    COMMENT "Building libuv"
    WORKING_DIRECTORY ${uv_build}
    ALWAYS 1
    ${use_terminal_arg}
  )

  install(CODE "execute_process(
    COMMAND ${CMAKE_MAKE_PROGRAM} install
    WORKING_DIRECTORY ${uv_build}
    )"
  )

  if ( CMAKE_TOOLCHAIN_FILE )
    set(toolchain_arg -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
  else ()
    set(toolchain_arg)
  endif ()

  if ( CMAKE_C_COMPILER_LAUNCHER )
    set(cmake_c_compiler_launcher_arg
        -DCMAKE_C_COMPILER_LAUNCHER:path=${CMAKE_C_COMPILER_LAUNCHER})
  else ()
    set(cmake_c_compiler_launcher_arg)
  endif ()

  if ( CMAKE_CXX_COMPILER_LAUNCHER )
    set(cmake_cxx_compiler_launcher_arg
        -DCMAKE_CXX_COMPILER_LAUNCHER:path=${CMAKE_CXX_COMPILER_LAUNCHER})
  else ()
    set(cmake_cxx_compiler_launcher_arg)
  endif ()

  execute_process(
      COMMAND
        ${CMAKE_COMMAND}
        -G${CMAKE_GENERATOR}
        ${toolchain_arg}
        ${cmake_c_compiler_launcher_arg}
        ${cmake_cxx_compiler_launcher_arg}
	-DBUILD_TESTING=OFF
        -DCMAKE_BUILD_TYPE:string=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX:path=${uv_install}
        ${uv_src}
      WORKING_DIRECTORY ${uv_build}
      RESULT_VARIABLE uv_cmake_result
      ERROR_VARIABLE UV_CMAKE_OUTPUT
      OUTPUT_VARIABLE UV_CMAKE_OUTPUT
      ERROR_STRIP_TRAILING_WHITESPACE
      OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  message("\n********** Begin libuv External Project CMake Output ************")
  message("\n${UV_CMAKE_OUTPUT}")
  message("\n*********** End libuv External Project CMake Output *************")
  message("\n")

  if (uv_cmake_result)
    message(FATAL_ERROR "libuv CMake configuration failed")
  endif ()

  add_library(libuv_a STATIC IMPORTED)
  set_property(TARGET libuv_a PROPERTY IMPORTED_LOCATION
    ${uv_build}/libuv_a${static_ext})
  add_dependencies(libuv_a project_uv)

  set(LIBUV_FOUND true)
  set(LIBUV_LIBRARIES libuv_a CACHE STRING "libuv libs" FORCE)
  set(LIBUV_INCLUDE_DIRS "${uv_src}/include" CACHE STRING "libuv includes" FORCE)
  
endif ()

if ( LIBUV_FOUND )
  include_directories(AFTER ${LIBUV_INCLUDE_DIRS})
  set(zeekdeps ${zeekdeps} ${LIBUV_LIBRARIES})
else()
  message(FATAL_ERROR "Failed to find libuv")
endif()

########################################################################
## Including subdirectories.
########################################################################

set(bro_SUBDIR_LIBS CACHE INTERNAL "subdir libraries" FORCE)
set(bro_PLUGIN_LIBS CACHE INTERNAL "plugin libraries" FORCE)

add_subdirectory(analyzer)
add_subdirectory(broker)
add_subdirectory(zeekygen)
add_subdirectory(file_analysis)
add_subdirectory(input)
add_subdirectory(iosource)
add_subdirectory(logging)
add_subdirectory(probabilistic)

set(bro_SUBDIRS
    # Order is important here.
    ${bro_PLUGIN_LIBS}
    ${bro_SUBDIR_LIBS}
)

if ( NOT bro_HAVE_OBJECT_LIBRARIES )
    foreach (_plugin ${bro_PLUGIN_LIBS})
        string(REGEX REPLACE "plugin-" "" _plugin "${_plugin}")
        string(REGEX REPLACE "-" "_" _plugin "${_plugin}")
        set(_decl "namespace plugin { namespace ${_plugin} { class Plugin; extern Plugin plugin; } };")
        set(_use "i += (size_t)(&(plugin::${_plugin}::plugin));")
        set(__BRO_DECL_PLUGINS "${__BRO_DECL_PLUGINS}${_decl}\n")
        set(__BRO_USE_PLUGINS "${__BRO_USE_PLUGINS}${_use}\n")
    endforeach()

    configure_file(plugins.cc.in ${CMAKE_CURRENT_BINARY_DIR}/plugins.cc)
    set(PLUGIN_INIT ${CMAKE_CURRENT_BINARY_DIR}/plugins.cc)
endif()

########################################################################
## bro target

find_package (Threads)

# Avoid CMake warning about "3rdparty" looking like a number.

cmake_policy(PUSH)

if (POLICY CMP0012)
cmake_policy(SET CMP0012 NEW)
endif ()

# This macro stores associated headers for any C/C++ source files given
# as arguments (past _var) as a list in the CMake variable named "_var".
macro(COLLECT_HEADERS _var)
    foreach (src ${ARGN})
        get_filename_component(ext ${src} EXT)
        if ("${ext}" STREQUAL ".cc" OR "${ext}" STREQUAL ".c")
            get_filename_component(base ${src} NAME_WE)
            get_filename_component(dir ${src} PATH)
            if (NOT "${dir}")
                set(dir ${CMAKE_CURRENT_SOURCE_DIR})
            endif ()
            set(header "${dir}/${base}.h")
            if (EXISTS ${header})
                list(APPEND ${_var} ${header})
            endif ()
        endif ()
    endforeach ()
endmacro(COLLECT_HEADERS _var)

cmake_policy(POP)

# define a command that's used to run the make_dbg_constants.py script
# building the bro binary depends on the outputs of this script
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdConstants.h
                          ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdInfoConstants.cc
                   COMMAND ${PYTHON_EXECUTABLE}
                   ARGS ${CMAKE_CURRENT_SOURCE_DIR}/make_dbg_constants.py
                        ${CMAKE_CURRENT_SOURCE_DIR}/DebugCmdInfoConstants.in
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make_dbg_constants.py
                           ${CMAKE_CURRENT_SOURCE_DIR}/DebugCmdInfoConstants.in
                   COMMENT "[Python] Processing debug commands"
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set_source_files_properties(nb_dns.c PROPERTIES COMPILE_FLAGS
                            -fno-strict-aliasing)

set(MAIN_SRCS
    main.cc
    net_util.cc
    util.cc
    module_util.cc
    Anon.cc
    Attr.cc
    Base64.cc
    Brofiler.cc
    BroString.cc
    CCL.cc
    CompHash.cc
    Conn.cc
    ConvertUTF.c
    DFA.cc
    DbgBreakpoint.cc
    DbgHelp.cc
    DbgWatch.cc
    Debug.cc
    DebugCmds.cc
    DebugLogger.cc
    Desc.cc
    Dict.cc
    Discard.cc
    DNS_Mgr.cc
    EquivClass.cc
    Event.cc
    EventHandler.cc
    EventLauncher.cc
    EventRegistry.cc
    Expr.cc
    File.cc
    Flare.cc
    Frag.cc
    Frame.cc
    Func.cc
    Hash.cc
    ID.cc
    IntSet.cc
    IP.cc
    IPAddr.cc
    Reporter.cc
    NFA.cc
    Net.cc
    NetVar.cc
    Obj.cc
    OpaqueVal.cc
    PacketFilter.cc
    Pipe.cc
    PolicyFile.cc
    PrefixTable.cc
    PriorityQueue.cc
    RandTest.cc
    RE.cc
    Reassem.cc
    Rule.cc
    RuleAction.cc
    RuleCondition.cc
    RuleMatcher.cc
    SmithWaterman.cc
    Scope.cc
    SerializationFormat.cc
    Sessions.cc
    Notifier.cc
    Stats.cc
    Stmt.cc
    Tag.cc
    Timer.cc
    Traverse.cc
    Trigger.cc
    TunnelEncapsulation.cc
    Type.cc
    UID.cc
    Val.cc
    Var.cc
    WeirdState.cc
    bsd-getopt-long.c
    bro_inet_ntop.c
    cq.c
    patricia.c
    setsignal.c
    PacketDumper.cc
    strsep.c
    modp_numtoa.c
    siphash24.c

    threading/BasicThread.cc
    threading/Formatter.cc
    threading/Manager.cc
    threading/MsgThread.cc
    threading/SerialTypes.cc
    threading/formatters/Ascii.cc
    threading/formatters/JSON.cc

    plugin/Component.cc
    plugin/ComponentManager.h
    plugin/TaggedComponent.h
    plugin/Manager.cc
    plugin/Plugin.cc

    nb_dns.c
    digest.h
)

set(THIRD_PARTY_SRCS
    3rdparty/sqlite3.c
)

set(bro_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/version.c
    ${BIF_SRCS}
    ${BINPAC_AUXSRC}
    ${BINPAC_OUTPUTS}
    ${TRANSFORMED_BISON_OUTPUTS}
    ${FLEX_RuleScanner_OUTPUTS}
    ${FLEX_RuleScanner_INPUT}
    ${BISON_RuleParser_INPUT}
    ${FLEX_REScanner_OUTPUTS}
    ${FLEX_REScanner_INPUT}
    ${BISON_REParser_INPUT}
    ${FLEX_Scanner_OUTPUTS}
    ${FLEX_Scanner_INPUT}
    ${BISON_Parser_INPUT}
    ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdConstants.h
    ${PLUGIN_INIT}
    ${THIRD_PARTY_SRCS}
    ${MAIN_SRCS}
)

collect_headers(bro_HEADERS ${bro_SRCS})

if ( bro_HAVE_OBJECT_LIBRARIES )
    add_executable(zeek ${bro_SRCS} ${bro_HEADERS} ${bro_SUBDIRS})
    target_link_libraries(zeek ${zeekdeps} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
else ()
    add_executable(zeek ${bro_SRCS} ${bro_HEADERS})
    target_link_libraries(zeek ${bro_SUBDIRS} ${zeekdeps} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
endif ()

if ( NOT "${bro_LINKER_FLAGS}" STREQUAL "" )
    set_target_properties(zeek PROPERTIES LINK_FLAGS "${bro_LINKER_FLAGS}")
endif ()

install(TARGETS zeek DESTINATION bin)

# Install wrapper script for Bro-to-Zeek renaming.
include(InstallSymlink)
InstallSymlink("${CMAKE_INSTALL_PREFIX}/bin/zeek-wrapper" "${CMAKE_INSTALL_PREFIX}/bin/bro")

set(BRO_EXE zeek
    CACHE STRING "Zeek executable binary" FORCE)

set(BRO_EXE_PATH ${CMAKE_CURRENT_BINARY_DIR}/zeek
    CACHE STRING "Path to Zeek executable binary" FORCE)

# Older plugins may still use `bro` in unit tests.
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                "${CMAKE_CURRENT_BINARY_DIR}/../zeek-wrapper.in"
                "${CMAKE_CURRENT_BINARY_DIR}/bro")

# Target to create all the autogenerated files.
add_custom_target(generate_outputs_stage1)
add_dependencies(generate_outputs_stage1 ${bro_ALL_GENERATED_OUTPUTS})

# Target to create the joint includes files that pull in the bif code.
bro_bif_create_includes(generate_outputs_stage2a ${CMAKE_CURRENT_BINARY_DIR} "${bro_AUTO_BIFS}")
bro_bif_create_register(generate_outputs_stage2b ${CMAKE_CURRENT_BINARY_DIR} "${bro_REGISTER_BIFS}")
add_dependencies(generate_outputs_stage2a generate_outputs_stage1)
add_dependencies(generate_outputs_stage2b generate_outputs_stage1)

# Global target to trigger creation of autogenerated code.
add_custom_target(generate_outputs)
add_dependencies(generate_outputs generate_outputs_stage2a generate_outputs_stage2b)

# Build __load__.zeek files for standard *.bif.zeek.
bro_bif_create_loader(bif_loader "${bro_BASE_BIF_SCRIPTS}")
add_dependencies(bif_loader ${bro_SUBDIRS})
add_dependencies(zeek bif_loader)

# Build __load__.zeek files for plugins/*.bif.zeek.
bro_bif_create_loader(bif_loader_plugins "${bro_PLUGIN_BIF_SCRIPTS}")
add_dependencies(bif_loader_plugins ${bro_SUBDIRS})
add_dependencies(zeek bif_loader_plugins)

# Install *.bif.zeek.
install(DIRECTORY ${CMAKE_BINARY_DIR}/scripts/base/bif DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH}/base)

# Create plugin directory at install time.
install(DIRECTORY DESTINATION ${BRO_PLUGIN_INSTALL_PATH})

# Make clean removes the bif directory.
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${CMAKE_BINARY_DIR}/scripts/base/bif)

# Remove some stale files and scripts that previous Bro versions put in
# place, yet make confuse us now. This makes upgrading easier.
install(CODE "
   file(REMOVE_RECURSE
       ${ZEEK_SCRIPT_INSTALL_PATH}/base/frameworks/logging/writers/dataseries.bro
       ${ZEEK_SCRIPT_INSTALL_PATH}/base/frameworks/logging/writers/elasticsearch.bro
       ${ZEEK_SCRIPT_INSTALL_PATH}/policy/tuning/logs-to-elasticsearch.bro
   )
")

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        DESTINATION include/zeek
        FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.pac"
        PATTERN "3rdparty/*" EXCLUDE
)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
        DESTINATION include/zeek
        FILES_MATCHING
        PATTERN "*.bif.func_h"
        PATTERN "*.bif.netvar_h"
        PATTERN "*.bif.h"
        PATTERN "CMakeFiles" EXCLUDE
)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/fifo_map.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/json.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/sqlite3.h
        DESTINATION include/zeek/3rdparty
)

########################################################################
## Clang-tidy target now that we have all of the sources

add_clang_tidy_files(${MAIN_SRCS})

# At this point we have included all of the cc files in src, all of the BinPAC
# (*.pac.cc) files, and most of the generated code for BIFs (not including
# *.bif.register.cc)
create_clang_tidy_target()
