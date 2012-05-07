include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

configure_file(version.c.in ${CMAKE_CURRENT_BINARY_DIR}/version.c)

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
             VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
flex_target(BIFScanner builtin-func.l ${CMAKE_CURRENT_BINARY_DIR}/bif_lex.cc)
add_flex_bison_dependency(BIFScanner BIFParser)

# Rule parser/scanner
bison_target(RuleParser rule-parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/rup.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/rup.h
             VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/rule_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rup.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/rule-parse.cc
                         rules_ rules_)
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rup.h
                         ${CMAKE_CURRENT_BINARY_DIR}/rule-parse.h
                         rules_ rules_)
flex_target(RuleScanner rule-scan.l ${CMAKE_CURRENT_BINARY_DIR}/rule-scan.cc
            COMPILE_FLAGS "-Prules_")

# RE parser/scanner
bison_target(REParser re-parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/rep.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/re-parse.h
             VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/re_parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rep.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/re-parse.cc
                         re_ RE_)
flex_target(REScanner re-scan.l ${CMAKE_CURRENT_BINARY_DIR}/re-scan.cc
            COMPILE_FLAGS "-Pre_")
add_flex_bison_dependency(REScanner REParser)

# Parser/Scanner
bison_target(Parser parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/p.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/broparse.h
             VERBOSE ${CMAKE_CURRENT_BINARY_DIR}/parse.output
             COMPILE_FLAGS "${BISON_FLAGS}")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/p.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/parse.cc
                         bro yy)
flex_target(Scanner scan.l ${CMAKE_CURRENT_BINARY_DIR}/scan.cc
            COMPILE_FLAGS "-Pbro")

########################################################################
## bifcl (BIF compiler) target

set(bifcl_SRCS
   ${BISON_BIFParser_INPUT}
   ${FLEX_BIFScanner_INPUT}
   ${BISON_BIFParser_OUTPUTS}
   ${FLEX_BIFScanner_OUTPUTS}
   bif_arg.cc
   module_util.cc
   bif_arg.h
   module_util.h
)

add_executable(bifcl ${bifcl_SRCS})

target_link_libraries(bifcl)

########################################################################
## bifcl-dependent targets

# A macro to define a command that uses the BIF compiler to produce
# C++ segments and Bro language declarations from .bif file
# The outputs are appended to list ALL_BIF_OUTPUTS
# Outputs that should be installed are appended to INSTALL_BIF_OUTPUTS
macro(BIF_TARGET bifInput)
    get_bif_output_files(${bifInput} bifOutputs)
    add_custom_command(OUTPUT ${bifOutputs}
                       COMMAND bifcl
                       ARGS ${CMAKE_CURRENT_SOURCE_DIR}/${bifInput} || (rm -f ${bifOutputs} && exit 1)
                       # In order be able to run bro from the build directory,
                       # the generated bro script needs to be inside a
                       # a directory tree named the same way it will be
                       # referenced from an @load.
                       COMMAND "${CMAKE_COMMAND}"
                       ARGS -E copy ${bifInput}.bro base/${bifInput}.bro
                       COMMAND "${CMAKE_COMMAND}"
                       ARGS -E remove -f ${bifInput}.bro
                       DEPENDS ${bifInput}
                       DEPENDS bifcl
                       COMMENT "[BIFCL] Processing ${bifInput}"
    )
    list(APPEND ALL_BIF_OUTPUTS ${bifOutputs})
    list(APPEND INSTALL_BIF_OUTPUTS
         ${CMAKE_CURRENT_BINARY_DIR}/base/${bifInput}.bro)
endmacro(BIF_TARGET)

# returns a list of output files that bifcl will produce
# for given input file in ${outputFileVar}
macro(GET_BIF_OUTPUT_FILES inputFile outputFileVar)
    set(${outputFileVar}
        base/${inputFile}.bro
        ${inputFile}.func_def
        ${inputFile}.func_h
        ${inputFile}.func_init
        ${inputFile}.netvar_def
        ${inputFile}.netvar_h
        ${inputFile}.netvar_init
    )
endmacro(GET_BIF_OUTPUT_FILES)

set(BIF_SRCS
    bro.bif
    logging.bif
    event.bif
    const.bif
    types.bif
    strings.bif
    reporter.bif
)

foreach (bift ${BIF_SRCS})
    bif_target(${bift})
endforeach ()

########################################################################
## BinPAC-dependent targets

set(BINPAC_AUXSRC
    binpac.pac
    bro.pac
    binpac_bro.h
)

# A macro to define a command that uses the BinPac compiler to
# produce C++ code that implements a protocol parser/analyzer
# The outputs of the command are appended to list ALL_BINPAC_OUTPUTS
# All arguments to this macro are appended to list ALL_BINPAC_INPUTS
macro(BINPAC_TARGET pacFile)
    get_filename_component(basename ${pacFile} NAME_WE)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.h
                              ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.cc
                       COMMAND ${BinPAC_EXE}
                       ARGS -q -d ${CMAKE_CURRENT_BINARY_DIR}
                            -I ${CMAKE_CURRENT_SOURCE_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR}/${pacFile}
                       DEPENDS ${BinPAC_EXE} ${pacFile}
                               ${BINPAC_AUXSRC} ${ARGN}
                       COMMENT "[BINPAC] Processing ${pacFile}"
    )
    list(APPEND ALL_BINPAC_INPUTS ${ARGV})
    list(APPEND ALL_BINPAC_OUTPUTS
         ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.h
         ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.cc) 
endmacro(BINPAC_TARGET)

binpac_target(binpac-lib.pac)
binpac_target(binpac_bro-lib.pac)
binpac_target(bittorrent.pac
    bittorrent-protocol.pac bittorrent-analyzer.pac)
binpac_target(dce_rpc.pac
    dce_rpc-protocol.pac dce_rpc-analyzer.pac epmapper.pac)
binpac_target(dce_rpc_simple.pac
    dce_rpc-protocol.pac epmapper.pac)
binpac_target(dhcp.pac
    dhcp-protocol.pac dhcp-analyzer.pac)
binpac_target(dns.pac
    dns-protocol.pac dns-analyzer.pac)
binpac_target(dns_tcp.pac
    dns.pac)
binpac_target(http.pac
    http-protocol.pac http-analyzer.pac)
binpac_target(ncp.pac)
binpac_target(netflow.pac
    netflow-protocol.pac netflow-analyzer.pac)
binpac_target(smb.pac
    smb-protocol.pac smb-pipe.pac smb-mailslot.pac)
binpac_target(ssl.pac
    ssl-defs.pac ssl-protocol.pac ssl-analyzer.pac)
binpac_target(syslog.pac
    syslog-protocol.pac syslog-analyzer.pac)

########################################################################
## bro target

find_package (Threads)

# This macro stores associated headers for any C/C++ source files given
# as arguments (past _var) as a list in the CMake variable named "_var".
macro(COLLECT_HEADERS _var)
    foreach (src ${ARGN})
        get_filename_component(ext ${src} EXT)
        if (${ext} STREQUAL ".cc" OR ${ext} STREQUAL ".c")
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

# define a command that's used to run the make_dbg_constants.pl script
# building the bro binary depends on the outputs of this script
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdConstants.h
                          ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdInfoConstants.cc
                   COMMAND ${PERL_EXECUTABLE}
                   ARGS ${CMAKE_CURRENT_SOURCE_DIR}/make_dbg_constants.pl
                        ${CMAKE_CURRENT_SOURCE_DIR}/DebugCmdInfoConstants.in
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make_dbg_constants.pl
                           ${CMAKE_CURRENT_SOURCE_DIR}/DebugCmdInfoConstants.in
                   COMMENT "[Perl] Processing debug commands"
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set_source_files_properties(nb_dns.c PROPERTIES COMPILE_FLAGS
                            -fno-strict-aliasing)

set(bro_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/version.c
    ${BIF_SRCS}
    ${ALL_BIF_OUTPUTS}
    ${BINPAC_AUXSRC}
    ${ALL_BINPAC_INPUTS}
    ${ALL_BINPAC_OUTPUTS}
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
    main.cc
    net_util.cc
    util.cc
    module_util.cc
    Analyzer.cc
    Anon.cc
    ARP.cc
    Attr.cc
    BackDoor.cc
    Base64.cc
    BitTorrent.cc
    BitTorrentTracker.cc
    BPF_Program.cc
    BroDoc.cc
    BroDocObj.cc
    Brofiler.cc
    BroString.cc
    CCL.cc
    ChunkedIO.cc
    CompHash.cc
    Conn.cc
    ConnSizeAnalyzer.cc
    ContentLine.cc
    DCE_RPC.cc
    DFA.cc
    DHCP-binpac.cc
    DNS.cc
    DNS-binpac.cc
    DNS_Mgr.cc
    DbgBreakpoint.cc
    DbgHelp.cc
    DbgWatch.cc
    Debug.cc
    DebugCmds.cc
    DebugLogger.cc
    Desc.cc
    Dict.cc
    Discard.cc
    DPM.cc
    EquivClass.cc
    Event.cc
    EventHandler.cc
    EventLauncher.cc
    EventRegistry.cc
    Expr.cc
    FTP.cc
    File.cc
    FileAnalyzer.cc
    Finger.cc
    FlowSrc.cc
    Frag.cc
    Frame.cc
    Func.cc
    Gnutella.cc
    HTTP.cc
    HTTP-binpac.cc
    Hash.cc
    ICMP.cc
    ID.cc
    Ident.cc
    IntSet.cc
    InterConn.cc
    IOSource.cc
    IP.cc
    IPAddr.cc
    IRC.cc
    List.cc
    Reporter.cc
    Login.cc
    MIME.cc
    NCP.cc
    NFA.cc
    NFS.cc
    NTP.cc
    NVT.cc
    Net.cc
    NetVar.cc
    NetbiosSSN.cc
    Obj.cc
    OSFinger.cc
    PacketFilter.cc
    PacketSort.cc
    PersistenceSerializer.cc
    PktSrc.cc
    PIA.cc
    PolicyFile.cc
    POP3.cc
    Portmap.cc
    PrefixTable.cc
    PriorityQueue.cc
    Queue.cc
    RandTest.cc
    RE.cc
    RPC.cc
    Reassem.cc
    RemoteSerializer.cc
    Rlogin.cc
    RSH.cc
    Rule.cc
    RuleAction.cc
    RuleCondition.cc
    RuleMatcher.cc
    ScriptAnaly.cc
    SmithWaterman.cc
    SMB.cc
    SMTP.cc
    SSH.cc
    SSL.cc
    Scope.cc
    SerializationFormat.cc
    SerialObj.cc
    Serializer.cc
    Sessions.cc
    StateAccess.cc
    Stats.cc
    SteppingStone.cc
    Stmt.cc
    Syslog-binpac.cc
    TCP.cc
    TCP_Endpoint.cc
    TCP_Reassembler.cc
    Telnet.cc
    Timer.cc
    Traverse.cc
    Trigger.cc
    Type.cc
    UDP.cc
    Val.cc
    Var.cc
    XDR.cc
    ZIP.cc
    bsd-getopt-long.c
    bro_inet_ntop.c
    cq.c
    patricia.c
    setsignal.c
    PacketDumper.cc
    strsep.c
    modp_numtoa.c

    threading/BasicThread.cc
    threading/Manager.cc
    threading/MsgThread.cc
    threading/SerialTypes.cc

    logging/Manager.cc
    logging/WriterBackend.cc
    logging/WriterFrontend.cc
    logging/writers/Ascii.cc
    logging/writers/None.cc

    nb_dns.c
    digest.h
)

collect_headers(bro_HEADERS ${bro_SRCS})

add_definitions(-DBRO_SCRIPT_INSTALL_PATH="${BRO_SCRIPT_INSTALL_PATH}")
add_definitions(-DBRO_SCRIPT_SOURCE_PATH="${BRO_SCRIPT_SOURCE_PATH}")
add_definitions(-DBRO_BUILD_PATH="${CMAKE_CURRENT_BINARY_DIR}")

add_executable(bro ${bro_SRCS} ${bro_HEADERS})

target_link_libraries(bro ${brodeps} ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS bro DESTINATION bin)
install(FILES ${INSTALL_BIF_OUTPUTS} DESTINATION ${BRO_SCRIPT_INSTALL_PATH}/base)

set(BRO_EXE bro
    CACHE STRING "Bro executable binary" FORCE)
