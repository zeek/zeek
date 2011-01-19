include_directories(${CMAKE_CURRENT_SOURCE_DIR}
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
   ${BISON_BIFParser_OUTPUTS}
   ${FLEX_BIFScanner_OUTPUTS}
   bif_arg.cc
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
                       ARGS ${CMAKE_CURRENT_SOURCE_DIR}/${bifInput} 
                       DEPENDS ${bifInput}
                       COMMENT "[BIFCL] Processing ${bifInput}"
    )
    list(APPEND ALL_BIF_OUTPUTS ${bifOutputs})
    list(APPEND INSTALL_BIF_OUTPUTS
         ${CMAKE_CURRENT_BINARY_DIR}/${bifInput}.bro)
endmacro(BIF_TARGET)

# returns a list of output files that bifcl will produce
# for given input file in ${outputFileVar}
macro(GET_BIF_OUTPUT_FILES inputFile outputFileVar)
    set(${outputFileVar}
        ${inputFile}.bro
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
    event.bif
    const.bif
    common-rw.bif
    finger-rw.bif
    ident-rw.bif
    dns-rw.bif
    ftp-rw.bif
    smtp-rw.bif
    http-rw.bif
    strings.bif
    smb-rw.bif
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
macro(BINPAC_TARGET pacFile)
    get_filename_component(basename ${pacFile} NAME_WE)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.h
                              ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.cc
                       COMMAND ${BinPAC_EXE}
                       ARGS -d ${CMAKE_CURRENT_BINARY_DIR}
                            -I ${CMAKE_CURRENT_SOURCE_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR}/${pacFile}
                       DEPENDS ${BinPAC_EXE} ${pacFile}
                               ${BINPAC_AUXSRC} ${ARGN}
                       COMMENT "[BINPAC] Processing ${pacFile}"
    )
    list(APPEND ALL_BINPAC_OUTPUTS
         ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.h
         ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.cc) 
endmacro(BINPAC_TARGET)

binpac_target(binpac-lib.pac)
binpac_target(binpac_bro-lib.pac)
binpac_target(bittorrent.pac
    bittorrent-protocol.pac bittorrent-analyzer.pac)
binpac_target(dce_rpc.pac
    dce_rpc-protocol.pac dce_rpc-analyzer.pac)
binpac_target(dce_rpc_simple.pac
    dce_rpc-protocol.pac)
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
binpac_target(rpc.pac
    rpc-analyzer.pac portmap-analyzer.pac)
binpac_target(smb.pac
    smb-protocol.pac smb-pipe.pac smb-mailslot.pac)
binpac_target(ssl.pac
    ssl-defs.pac ssl-protocol.pac ssl-analyzer.pac)
binpac_target(ssl-record-layer.pac
    ssl-defs.pac ssl.pac)

########################################################################
## bro target

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

set(dns_SRCS nb_dns.c nb_dns.h)

set(openssl_SRCS X509.cc SSLCiphers.cc SSLInterpreter.cc SSLProxy.cc
                 SSLv2.cc SSLv3.cc SSLv3Automaton.cc)

if (USE_NMALLOC)
    set(malloc_SRCS malloc.c)
endif ()

set(bro_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/version.c
    ${ALL_BIF_OUTPUTS}
    ${ALL_BINPAC_OUTPUTS}
    ${TRANSFORMED_BISON_OUTPUTS}
    ${FLEX_RuleScanner_OUTPUTS}
    ${FLEX_REScanner_OUTPUTS}
    ${FLEX_Scanner_OUTPUTS}
    ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdConstants.h
    main.cc
    net_util.cc
    util.cc
    Active.cc
    Analyzer.cc
    Anon.cc
    ARP.cc
    Attr.cc
    BackDoor.cc
    Base64.cc
    BitTorrent.cc
    BitTorrentTracker.cc
    BPF_Program.cc
    BroString.cc
    CCL.cc
    ChunkedIO.cc
    CompHash.cc
    Conn.cc
    ConnCompressor.cc
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
    IRC.cc
    List.cc
    Logger.cc
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
    SSL-binpac.cc
    Scope.cc
    SerializationFormat.cc
    SerialObj.cc
    Serializer.cc
    Sessions.cc
    StateAccess.cc
    Stats.cc
    SteppingStone.cc
    Stmt.cc
    TCP.cc
    TCP_Endpoint.cc
    TCP_Reassembler.cc
    TCP_Rewriter.cc
    Telnet.cc
    Timer.cc
    Traverse.cc
    Trigger.cc
    TwoWise.cc
    Type.cc
    UDP.cc
    Val.cc
    Var.cc
    XDR.cc
    ZIP.cc
    bsd-getopt-long.c
    cq.c
    md5.c
    patricia.c
    setsignal.c
    UDP_Rewriter.cc
    DNS_Rewriter.cc
    PacketDumper.cc
    Rewriter.cc
    strsep.c
    ${dns_SRCS}
    ${malloc_SRCS}
    ${openssl_SRCS}
)

add_definitions(-DPOLICYDEST="${POLICYDIR}")

add_executable(bro ${bro_SRCS})

set(brolibs
    ${BinPAC_LIBRARY}
    ${PCAP_LIBRARY}
    ${OpenSSL_LIBRARIES}
    ${BIND_LIBRARY}
    ${OPTLIBS}
)

target_link_libraries(bro ${brolibs})

install(TARGETS bro DESTINATION bin)
install(FILES ${INSTALL_BIF_OUTPUTS} DESTINATION ${POLICYDIR})

set(BRO_EXE bro
    CACHE STRING "Bro executable binary" FORCE)
