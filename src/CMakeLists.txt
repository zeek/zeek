include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR}/include
                    ${CMAKE_CURRENT_BINARY_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}/include
)

# Force creation of includes symlink. This can't just be in the src directory
# because MSVC will end up with an include loop.
execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory
                "${CMAKE_CURRENT_SOURCE_DIR}/include")
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                ".."
                "${CMAKE_CURRENT_SOURCE_DIR}/include/zeek")

# Allows header file inclusion via zeek/ within the build tree
execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory
                "${CMAKE_CURRENT_BINARY_DIR}/include")
execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
                ".."
                "${CMAKE_CURRENT_BINARY_DIR}/include/zeek")

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
    set(args "\"/extern char.*getenv/d")
    set(args "${args}\;s/yylex/${yylexPrefix}lex/")
    set(args "${args}\;s/yy/${yyPrefix}/g\"" < ${inFile} > ${outFile})
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

if ( MSVC )
    set(SIGN_COMPARE_FLAG "/wd4018")
else()
    set(SIGN_COMPARE_FLAG "-Wno-sign-compare")
endif()

# BIF parser/scanner
bison_target(BIFParser builtin-func.y
             ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.h
             #VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
flex_target(BIFScanner builtin-func.l ${CMAKE_CURRENT_BINARY_DIR}/bif_lex.cc)
add_flex_bison_dependency(BIFScanner BIFParser)
set_property(SOURCE bif_lex.cc APPEND_STRING PROPERTY COMPILE_FLAGS "${SIGN_COMPARE_FLAG}")

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
set_property(SOURCE rule-scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "${SIGN_COMPARE_FLAG}")

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
set_property(SOURCE re-scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "${SIGN_COMPARE_FLAG}")

# Parser/Scanner
bison_target(Parser parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/p.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/zeekparse.h
             #VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/p.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/parse.cc
                         zeek yy)
flex_target(Scanner scan.l ${CMAKE_CURRENT_BINARY_DIR}/scan.cc
            COMPILE_FLAGS "-Pzeek")
set_property(SOURCE scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "${SIGN_COMPARE_FLAG}")

########################################################################
## bifcl-dependent targets

include(BifCl)

set(SUPERVISOR_SRCS supervisor/Supervisor.cc Pipe.cc)

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
    # The C++ loading BIF is treated like other top-level BIFs to give
    # us flexibility regarding when it's called.
    script_opt/CPP/CPP-load.bif
)

foreach (bift ${BIF_SRCS})
    bif_target(${bift} "standard")
endforeach ()

########################################################################
## BinPAC-dependent targets

include(BinPAC)

set(BINPAC_AUXSRC
    ${CMAKE_CURRENT_SOURCE_DIR}/binpac.pac
    ${CMAKE_CURRENT_SOURCE_DIR}/zeek.pac
    ${CMAKE_CURRENT_SOURCE_DIR}/binpac_zeek.h
)

binpac_target(binpac-lib.pac)
list(APPEND BINPAC_OUTPUTS "${BINPAC_OUTPUT_CC}")

binpac_target(binpac_zeek-lib.pac)
list(APPEND BINPAC_OUTPUTS "${BINPAC_OUTPUT_CC}")

########################################################################
## Gen-ZAM setup

include(Gen-ZAM)

set(GEN_ZAM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/script_opt/ZAM/Ops.in)

gen_zam_target(${GEN_ZAM_SRC})

########################################################################
## Including subdirectories.
########################################################################

option(USE_SQLITE "Should Zeek use SQLite?" ON)

set(bro_SUBDIR_LIBS CACHE INTERNAL "subdir libraries" FORCE)
set(bro_SUBDIR_DEPS CACHE INTERNAL "subdir dependencies" FORCE)
set(bro_PLUGIN_LIBS CACHE INTERNAL "plugin libraries" FORCE)
set(bro_PLUGIN_DEPS CACHE INTERNAL "plugin dependencies" FORCE)
set(bro_PLUGIN_LINK_LIBS CACHE INTERNAL "plugin link libraries" FORCE)

add_subdirectory(analyzer)
add_subdirectory(packet_analysis)
add_subdirectory(broker)
add_subdirectory(telemetry)
add_subdirectory(zeekygen)
add_subdirectory(file_analysis)
add_subdirectory(input)
add_subdirectory(iosource)
add_subdirectory(logging)
add_subdirectory(probabilistic)
add_subdirectory(session)

########################################################################
## Build in the discovered external plugins and create the autogenerated scripts.

set(PRELOAD_SCRIPT ${PROJECT_BINARY_DIR}/scripts/builtin-plugins/__preload__.zeek)
file(WRITE ${PRELOAD_SCRIPT} "# Warning, this is an autogenerated file!\n")
set(LOAD_SCRIPT ${PROJECT_BINARY_DIR}/scripts/builtin-plugins/__load__.zeek)
file(WRITE ${LOAD_SCRIPT} "# Warning, this is an autogenerated file!\n")

foreach (plugin_dir ${BUILTIN_PLUGIN_LIST})
    get_filename_component(plugin_name ${plugin_dir} NAME)

    if(IS_DIRECTORY "${plugin_dir}/cmake")
        set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${plugin_dir}/cmake")
    endif()

    add_subdirectory(${plugin_dir} ${CMAKE_CURRENT_BINARY_DIR}/builtin-plugins/${plugin_name})
endforeach()

install(FILES ${PRELOAD_SCRIPT} DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH}/builtin-plugins/)
install(FILES ${LOAD_SCRIPT} DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH}/builtin-plugins/)

########################################################################
## This has to happen after the parts for builtin plugins, or else
## symbols are missing when it goes to link the fuzzer binaries.
add_subdirectory(fuzzers)

########################################################################
## zeek target

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
# building the zeek binary depends on the outputs of this script
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

set(_gen_zeek_script_cpp ${CMAKE_CURRENT_BINARY_DIR}/../CPP-gen.cc)
add_custom_command(OUTPUT ${_gen_zeek_script_cpp}
		   COMMAND ${CMAKE_COMMAND} -E touch ${_gen_zeek_script_cpp})

if (!MSVC)
    set_source_files_properties(legacy-netvar-init.cc PROPERTIES COMPILE_FLAGS
                                -Wno-deprecated-declarations)
endif()

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
    DNS_Mapping.cc
    DNS_Mgr.cc
    EquivClass.cc
    Event.cc
    EventHandler.cc
    EventLauncher.cc
    EventRegistry.cc
    EventTrace.cc
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
    Overflow.cc
    PacketFilter.cc
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
    ScriptProfile.cc
    ScriptValidation.cc
    SerializationFormat.cc
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
    ZVal.cc

    ${SUPERVISOR_SRCS}

    threading/BasicThread.cc
    threading/Formatter.cc
    threading/Manager.cc
    threading/MsgThread.cc
    threading/SerialTypes.cc
    threading/formatters/Ascii.cc
    threading/formatters/JSON.cc

    plugin/Component.cc
    plugin/ComponentManager.h
    plugin/Manager.cc
    plugin/Plugin.cc

    script_opt/CPP/Attrs.cc
    script_opt/CPP/Consts.cc
    script_opt/CPP/DeclFunc.cc
    script_opt/CPP/Driver.cc
    script_opt/CPP/Emit.cc
    script_opt/CPP/Exprs.cc
    script_opt/CPP/Func.cc
    script_opt/CPP/GenFunc.cc
    script_opt/CPP/Inits.cc
    script_opt/CPP/InitsInfo.cc
    script_opt/CPP/RuntimeInits.cc
    script_opt/CPP/RuntimeInitSupport.cc
    script_opt/CPP/RuntimeOps.cc
    script_opt/CPP/RuntimeVec.cc
    script_opt/CPP/Stmts.cc
    script_opt/CPP/Tracker.cc
    script_opt/CPP/Types.cc
    script_opt/CPP/Util.cc
    script_opt/CPP/Vars.cc

    ${_gen_zeek_script_cpp}

    script_opt/Expr.cc
    script_opt/GenIDDefs.cc
    script_opt/IDOptInfo.cc
    script_opt/Inline.cc
    script_opt/ProfileFunc.cc
    script_opt/Reduce.cc
    script_opt/ScriptOpt.cc
    script_opt/Stmt.cc
    script_opt/TempVar.cc
    script_opt/UsageAnalyzer.cc
    script_opt/UseDefs.cc

    script_opt/ZAM/AM-Opt.cc
    script_opt/ZAM/Branches.cc
    script_opt/ZAM/BuiltIn.cc
    script_opt/ZAM/BuiltInSupport.cc
    script_opt/ZAM/Driver.cc
    script_opt/ZAM/Expr.cc
    script_opt/ZAM/Inst-Gen.cc
    script_opt/ZAM/Low-Level.cc
    script_opt/ZAM/Stmt.cc
    script_opt/ZAM/Support.cc
    script_opt/ZAM/Vars.cc
    script_opt/ZAM/ZBody.cc
    script_opt/ZAM/ZInst.cc
    script_opt/ZAM/ZOp.cc

    digest.h
)

set(THIRD_PARTY_SRCS
    3rdparty/bro_inet_ntop.c # Remove in v6.1.
    3rdparty/zeek_inet_ntop.c
    3rdparty/bsd-getopt-long.c
    3rdparty/ConvertUTF.c
    3rdparty/in_cksum.cc
    3rdparty/modp_numtoa.c
    3rdparty/patricia.c
    3rdparty/setsignal.c
    $<$<BOOL:USE_SQLITE>:3rdparty/sqlite3.c>
    3rdparty/strsep.c
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
  check_c_source_compiles("
      #if defined(__ARM_NEON__) || defined(__ARM_NEON)
      int main() { return 0; }
      #else
      #error
      #endif
  " test_arm_neon)

  if (test_arm_neon)
    list(APPEND HH_SRCS ../auxil/highwayhash/highwayhash/hh_neon.cc)
  endif ()

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
  if (MSVC)
    set(_avx_flag /arch:AVX2)
    # Using an undocumentd compiler flag: https://stackoverflow.com/questions/64053597/how-do-i-enable-sse4-1-and-sse3-but-not-avx-in-msvc/69328426#69328426
    set(_sse_flag /d2archSSE42)
  else()
    set(_avx_flag -mavx2)
    set(_sse_flag -msse4.1)
  endif()

  set_source_files_properties(../auxil/highwayhash/highwayhash/hh_avx2.cc PROPERTIES COMPILE_FLAGS
                              ${_avx_flag})
  set_source_files_properties(../auxil/highwayhash/highwayhash/hh_sse41.cc PROPERTIES COMPILE_FLAGS
                              ${_sse_flag})

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
    ${GEN_ZAM_SRC}
    ${GEN_ZAM_OUTPUT_H}
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
    ${CMAKE_CURRENT_BINARY_DIR}/ZAM-MethodDecls.h
    ${THIRD_PARTY_SRCS}
    ${HH_SRCS}
    ${MAIN_SRCS}
)

collect_headers(zeek_HEADERS ${zeek_SRCS})

add_library(zeek_objs OBJECT ${zeek_SRCS})

if (ZEEK_STANDALONE)
    add_executable(zeek main.cc
                $<TARGET_OBJECTS:zeek_objs>
                ${zeek_HEADERS}
                ${bro_SUBDIR_LIBS}
                ${bro_PLUGIN_LIBS}
    )
    target_link_libraries(zeek ${bro_PLUGIN_LINK_LIBS} ${zeekdeps} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

    # Export symbols from zeek executable for use by plugins
    set_target_properties(zeek PROPERTIES ENABLE_EXPORTS TRUE)

    if ( MSVC )
        set(WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif ()

    install(TARGETS zeek RUNTIME DESTINATION bin)

    set(BRO_EXE zeek
        CACHE STRING "Zeek executable binary" FORCE)

    set(BRO_EXE_PATH ${CMAKE_CURRENT_BINARY_DIR}/zeek
        CACHE STRING "Path to Zeek executable binary" FORCE)
endif()

if (NOT ZEEK_STANDALONE OR CONAN_EXPORTED)
    add_library(libzeek STATIC $<TARGET_OBJECTS:zeek_objs>
                                ${zeek_HEADERS}
                                ${bro_SUBDIR_LIBS}
                                ${bro_PLUGIN_LIBS})

    target_link_libraries(libzeek PUBLIC ${zeekdeps}
                                      ${CMAKE_THREAD_LIBS_INIT}
                                      ${CMAKE_DL_LIBS}
                                      ${bro_SUBDIR_LIBS}
                                      ${bro_PLUGIN_LIBS})

    target_include_directories(libzeek PUBLIC
                                    ${CMAKE_SOURCE_DIR}/zeek/src
                                    ${CMAKE_SOURCE_DIR}/zeek/src/include
                                    ${CMAKE_BINARY_DIR}
                                    ${CMAKE_BINARY_DIR}/zeek/src
                                    ${CMAKE_BINARY_DIR}/zeek/src/include)

    install(TARGETS libzeek LIBRARY DESTINATION lib)
endif()

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
install(DIRECTORY ${PROJECT_BINARY_DIR}/scripts/base/bif DESTINATION ${ZEEK_SCRIPT_INSTALL_PATH}/base)

# Create plugin directory at install time.
install(DIRECTORY DESTINATION ${BRO_PLUGIN_INSTALL_PATH})

# Make clean removes the bif directory.
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${PROJECT_BINARY_DIR}/scripts/base/bif)

# Remove some stale files and scripts that previous Zeek versions put in
# place, yet make confuse us now. This makes upgrading easier.
install(CODE "
   file(REMOVE_RECURSE
       ${ZEEK_SCRIPT_INSTALL_PATH}/base/frameworks/logging/writers/dataseries.bro
       ${ZEEK_SCRIPT_INSTALL_PATH}/base/frameworks/logging/writers/elasticsearch.bro
       ${ZEEK_SCRIPT_INSTALL_PATH}/policy/tuning/logs-to-elasticsearch.bro
   )
")

# Make sure to escape a bunch of special characters in the path before trying to use it as a
# regular expression below.
string(REGEX REPLACE "([][+.*()^])" "\\\\\\1" escaped_include_path "${CMAKE_CURRENT_SOURCE_DIR}/include/*")

if (WIN32)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/windows/usr.include/
            DESTINATION include/
            FILES_MATCHING
            PATTERN "*.h"
    )
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        DESTINATION include/zeek
        FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.pac"
        PATTERN "3rdparty/*" EXCLUDE
        # The "zeek -> ." symlink isn't needed in the install-tree
        REGEX "${escaped_include_path}$" EXCLUDE

	# FILES_MATCHING creates empty directories:
	# https://gitlab.kitware.com/cmake/cmake/-/issues/17122
	# Exclude the ones that this affects explicitly.
	PATTERN "script_opt/CPP/maint" EXCLUDE
	PATTERN "fuzzers/corpora" EXCLUDE
)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/
        DESTINATION include/zeek
        FILES_MATCHING
        PATTERN "*.bif.func_h"
        PATTERN "*.bif.netvar_h"
        PATTERN "*.bif.h"
        PATTERN "CMakeFiles" EXCLUDE
        # The "include/zeek -> .." symlink isn't needed in the install-tree
        REGEX "${escaped_include_path}$" EXCLUDE
)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/ConvertUTF.h
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/bro_inet_ntop.h # Remove in v6.1
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/zeek_inet_ntop.h
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/bsd-getopt-long.h
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/modp_numtoa.h
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/patricia.h
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/setsignal.h
        $<$<BOOL:USE_SQLITE>:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/sqlite3.h>
        ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/doctest.h
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
