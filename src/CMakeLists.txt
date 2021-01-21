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
    # Note: the supervisor BIF file is treated like other top-level BIFs
    # instead of contained in its own subdirectory CMake logic because
    # subdirectory BIFs are treated differently and don't support being called
    # *during* parsing (e.g. within an @if directive).
    supervisor/supervisor.bif
    # The packet analysis BIF is treated like other top-level BIFs because
    # it's needed before parsing the packet protocol scripts, which happen
    # very near to the start of parsing.
    packet_analysis/packet_analysis.bif
)

foreach (bift ${BIF_SRCS})
    bif_target(${bift} "standard")
endforeach ()

########################################################################
## BinPAC-dependent targets

include(BinPAC)

set(BINPAC_AUXSRC
    ${CMAKE_SOURCE_DIR}/src/binpac.pac
    ${CMAKE_SOURCE_DIR}/src/zeek.pac
    ${CMAKE_SOURCE_DIR}/src/binpac_zeek.h
)

binpac_target(binpac-lib.pac)
list(APPEND BINPAC_OUTPUTS "${BINPAC_OUTPUT_CC}")

binpac_target(binpac_zeek-lib.pac)
list(APPEND BINPAC_OUTPUTS "${BINPAC_OUTPUT_CC}")

########################################################################
## Including subdirectories.
########################################################################

set(bro_SUBDIR_LIBS CACHE INTERNAL "subdir libraries" FORCE)
set(bro_SUBDIR_DEPS CACHE INTERNAL "subdir dependencies" FORCE)
set(bro_PLUGIN_LIBS CACHE INTERNAL "plugin libraries" FORCE)
set(bro_PLUGIN_DEPS CACHE INTERNAL "plugin dependencies" FORCE)

add_subdirectory(analyzer)
add_subdirectory(packet_analysis)
add_subdirectory(broker)
add_subdirectory(zeekygen)
add_subdirectory(file_analysis)
add_subdirectory(input)
add_subdirectory(iosource)
add_subdirectory(logging)
add_subdirectory(probabilistic)

add_subdirectory(fuzzers)

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

set_source_files_properties(legacy-netvar-init.cc PROPERTIES COMPILE_FLAGS
                            -Wno-deprecated-declarations)

set(MAIN_SRCS
    digest.cc
    net_util.cc
    util.cc
    module_util.cc
    zeek-affinity.cc
    zeek-setup.cc
    Anon.cc
    Attr.cc
    Base64.cc
    BifReturnVal.cc
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
    List.cc
    Reporter.cc
    NFA.cc
    NetVar.cc
    Notifier.cc
    Obj.cc
    OpaqueVal.cc
    Options.cc
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
    RunState.cc
    ScannedFile.cc
    Scope.cc
    ScriptCoverageManager.cc
    SerializationFormat.cc
    Sessions.cc
    SmithWaterman.cc
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
    ZeekArgs.cc
    ZeekString.cc
    legacy-netvar-init.cc
    bsd-getopt-long.c
    bro_inet_ntop.c
    in_cksum.cc
    patricia.c
    setsignal.c
    strsep.c
    modp_numtoa.c

    supervisor/Supervisor.cc

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

    script_opt/Expr.cc
    script_opt/Inline.cc
    script_opt/ProfileFunc.cc
    script_opt/Reduce.cc
    script_opt/ScriptOpt.cc
    script_opt/Stmt.cc
    script_opt/TempVar.cc

    nb_dns.c
    digest.h
)

set(THIRD_PARTY_SRCS
    3rdparty/sqlite3.c
)

# Highwayhash. Highwayhash is a bit special since it has architecture dependent code...

set(HH_SRCS
    ../auxil/highwayhash/highwayhash/sip_hash.cc
    ../auxil/highwayhash/highwayhash/sip_tree_hash.cc
    ../auxil/highwayhash/highwayhash/scalar_sip_tree_hash.cc
    ../auxil/highwayhash/highwayhash/arch_specific.cc
    ../auxil/highwayhash/highwayhash/instruction_sets.cc
    ../auxil/highwayhash/highwayhash/nanobenchmark.cc
    ../auxil/highwayhash/highwayhash/os_specific.cc
    ../auxil/highwayhash/highwayhash/hh_portable.cc
)

if (${COMPILER_ARCHITECTURE} STREQUAL "arm")
  set_source_files_properties(${HH_SRCS} PROPERTIES COMPILE_FLAGS
                              -mfloat-abi=hard -march=armv7-a -mfpu=neon)
elseif (${COMPILER_ARCHITECTURE} STREQUAL "aarch64")
  list(APPEND HH_SRCS
       ../auxil/highwayhash/highwayhash/hh_neon.cc
  )
elseif (${COMPILER_ARCHITECTURE} STREQUAL "power")
  set_source_files_properties(../auxil/highwayhash/highwayhash/hh_vsx.cc PROPERTIES COMPILE_FLAGS
                              -mvsx)
  list(APPEND HH_SRCS
       ../auxil/highwayhash/highwayhash/hh_vsx.cc
  )
elseif(${COMPILER_ARCHITECTURE} STREQUAL "x86_64")
  set_source_files_properties(../auxil/highwayhash/highwayhash/hh_avx2.cc PROPERTIES COMPILE_FLAGS
                              -mavx2)
  set_source_files_properties(../auxil/highwayhash/highwayhash/hh_sse41.cc PROPERTIES COMPILE_FLAGS
                              -msse4.1)

  list(APPEND HH_SRCS
      ../auxil/highwayhash/highwayhash/hh_avx2.cc
      ../auxil/highwayhash/highwayhash/hh_sse41.cc
  )
endif ()

set(zeek_SRCS
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
    ${THIRD_PARTY_SRCS}
    ${HH_SRCS}
    ${MAIN_SRCS}
)

collect_headers(zeek_HEADERS ${zeek_SRCS})

add_library(zeek_objs OBJECT ${zeek_SRCS})

add_executable(zeek main.cc
               $<TARGET_OBJECTS:zeek_objs>
               ${zeek_HEADERS}
               ${bro_SUBDIR_LIBS}
               ${bro_PLUGIN_LIBS}
)
target_link_libraries(zeek ${zeekdeps} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
# Export symbols from zeek executable for use by plugins
set_target_properties(zeek PROPERTIES ENABLE_EXPORTS TRUE)

install(TARGETS zeek DESTINATION bin)

# Install wrapper script for Bro-to-Zeek renaming.
include(InstallSymlink)
InstallSymlink("${CMAKE_INSTALL_PREFIX}/bin/zeek-wrapper" "${CMAKE_INSTALL_PREFIX}/bin/bro")

set(BRO_EXE zeek
    CACHE STRING "Zeek executable binary" FORCE)

set(BRO_EXE_PATH ${CMAKE_CURRENT_BINARY_DIR}/zeek
    CACHE STRING "Path to Zeek executable binary" FORCE)

if ( NOT BINARY_PACKAGING_MODE )
    # Older plugins may still use `bro` in unit tests.
    execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                    "${CMAKE_CURRENT_BINARY_DIR}/../zeek-wrapper.in"
                    "${CMAKE_CURRENT_BINARY_DIR}/bro")
endif ()

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
add_dependencies(bif_loader ${bro_PLUGIN_DEPS} ${bro_SUBDIR_DEPS})
add_dependencies(zeek_objs bif_loader)

# Build __load__.zeek files for plugins/*.bif.zeek.
bro_bif_create_loader(bif_loader_plugins "${bro_PLUGIN_BIF_SCRIPTS}")
add_dependencies(bif_loader_plugins ${bro_PLUGIN_DEPS} ${bro_SUBDIR_DEPS})
add_dependencies(zeek_objs bif_loader_plugins)

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
        # The "zeek -> ." symlink isn't needed in the install-tree
        REGEX "^${CMAKE_CURRENT_SOURCE_DIR}/zeek$" EXCLUDE
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

########################################################################
## CTest setup.

# Scan all .cc files for TEST_CASE macros and generate CTest targets.
if (ENABLE_ZEEK_UNIT_TESTS)
    set(test_cases "")
    foreach (cc_file ${TIDY_SRCS})
        file (STRINGS ${cc_file} test_case_lines REGEX "TEST_CASE")
        foreach (line ${test_case_lines})
            string(REGEX REPLACE "TEST_CASE\\(\"(.+)\"\\)" "\\1" test_case "${line}")
            list(APPEND test_cases "${test_case}")
        endforeach ()
    endforeach ()
    list(LENGTH test_cases num_test_cases)
    MESSAGE(STATUS "-- Found ${num_test_cases} test cases for CTest")
    foreach (test_case ${test_cases})
        add_test(NAME "\"${test_case}\""
                 COMMAND zeek --test "--test-case=${test_case}")
    endforeach ()
endif ()
