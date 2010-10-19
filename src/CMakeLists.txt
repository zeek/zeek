find_package(FLEX REQUIRED) 
find_package(BISON REQUIRED)
find_package(PCAP REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
                    ${CMAKE_SOURCE_DIR}/binpac/lib
                    ${CMAKE_BINARY_DIR}/binpac/lib
                    )

find_program(SED_EXE sed)
if (NOT SED_EXE)
    message(FATAL_ERROR "sed required")
endif ()

macro(REPLACE_YY_PREFIX_TARGET inFile outFile yylexPrefix yyPrefix)
    set(args "'/extern char.*getenv/d\;s/yylex/${yylexPrefix}lex/\;s/yy/${yyPrefix}/g'" < ${inFile} > ${outFile})
    add_custom_command(OUTPUT ${outFile}
                       COMMAND ${SED_EXE}
                       ARGS ${args}
                       DEPENDS ${inFile}
                       COMMENT "[sed] replacing stuff in ${inFile}"
    )
endmacro(REPLACE_YY_PREFIX_TARGET)

bison_target(BIFParser builtin-func.y
             ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.h
             COMPILE_FLAGS "-t")
flex_target(BIFScanner builtin-func.l ${CMAKE_CURRENT_BINARY_DIR}/bif_lex.cc)
add_flex_bison_dependency(BIFScanner BIFParser)

bison_target(RuleParser rule-parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/rup.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/rup.h
             COMPILE_FLAGS "-t")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rup.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/rule-parse.cc
                         rules_ rules_)
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rup.h
                         ${CMAKE_CURRENT_BINARY_DIR}/rule-parse.h
                         rules_ rules_)
flex_target(RuleScanner rule-scan.l ${CMAKE_CURRENT_BINARY_DIR}/rule-scan.cc
            COMPILE_FLAGS "-Prules_")

bison_target(REParser re-parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/rep.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/re-parse.h
             COMPILE_FLAGS "-t")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/rep.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/re-parse.cc
                         re_ RE_)
flex_target(REScanner re-scan.l ${CMAKE_CURRENT_BINARY_DIR}/re-scan.cc
            COMPILE_FLAGS "-Pre_")
add_flex_bison_dependency(REScanner REParser)

bison_target(Parser parse.y
             ${CMAKE_CURRENT_BINARY_DIR}/p.cc
             HEADER ${CMAKE_CURRENT_BINARY_DIR}/broparse.h
             COMPILE_FLAGS "-t")
replace_yy_prefix_target(${CMAKE_CURRENT_BINARY_DIR}/p.cc
                         ${CMAKE_CURRENT_BINARY_DIR}/parse.cc
                         bro yy)

flex_target(Scanner scan.l ${CMAKE_CURRENT_BINARY_DIR}/scan.cc
            COMPILE_FLAGS "-Pbro")

configure_file (version.c.in ${CMAKE_CURRENT_BINARY_DIR}/version.c)

########### next target ###############

set(bifcl_SRCS
   ${BISON_BIFParser_OUTPUTS}
   ${FLEX_BIFScanner_OUTPUTS}
   bif_arg.cc
)

add_executable(bifcl ${bifcl_SRCS})

target_link_libraries(bifcl)

macro(BIF_TARGET bifInput)
    get_bif_output_files(${bifInput} bifOutputs)
    add_custom_command(OUTPUT ${bifOutputs}
                       COMMAND bifcl
                       ARGS ${CMAKE_CURRENT_SOURCE_DIR}/${bifInput} 
                       DEPENDS ${bifInput}
                       COMMENT "[BIFCL] Processing ${bifInput}"
    )
    list(APPEND ALL_BIF_OUTPUTS ${bifOutputs})
endmacro(BIF_TARGET)

macro(GET_BIF_OUTPUT_FILES inputFile outputFileVar)
    set(${outputFileVar}
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.bro 
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.func_def
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.func_h 
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.func_init 
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.netvar_def 
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.netvar_h 
        ${CMAKE_CURRENT_BINARY_DIR}/${inputFile}.netvar_init
    )
endmacro(GET_BIF_OUTPUT_FILES)

########## targets that needed bifcl ##########

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

foreach(bift ${BIF_SRCS})
    bif_target(${bift})
endforeach(bift)


########## targets that need binpac ##########

#TODO: need logic to find binpac when it's a separate component?

macro(BINPAC_TARGET pacFile)
    get_filename_component(basename ${pacFile} NAME_WE)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.h
                              ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.cc
                       COMMAND binpac
                       ARGS -d ${CMAKE_CURRENT_BINARY_DIR}
                            -I ${CMAKE_CURRENT_SOURCE_DIR}
                            ${pacFile}
                       DEPENDS binpac ${pacFile}
                       COMMENT "[BINPAC] Processing ${pacFile}"
    )
    list(APPEND ALL_BINPAC_OUTPUTS
         ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.h
         ${CMAKE_CURRENT_BINARY_DIR}/${basename}_pac.cc) 
endmacro(BINPAC_TARGET)

set(BINPAC_SRCS
    binpac-lib.pac
    binpac_bro-lib.pac
    bittorrent.pac
    dce_rpc.pac
    dce_rpc_simple.pac
    dhcp.pac
    dns.pac
    dns_tcp.pac
    http.pac
    ncp.pac
    netflow.pac
    rpc.pac
    smb.pac
    ssl.pac
    ssl-record-layer.pac
)

set(BINPAC_AUXSRC
    binpac.pac
    bro.pac
    binpac_bro.h
)

set(BINPAC_RPC_AUXSRC
    bittorrent-protocol.pac bittorrent-analyzer.pac
    dce_rpc-analyzer.pac dce_rpc-protocol.pac
    dhcp-analyzer.pac dhcp-protocol.pac
    dns-analyzer.pac dns-protocol.pac
    epmapper.pac
    http-analyzer.pac http-protocol.pac http.pac
    netflow-protocol.pac netflow-analyzer.pac
    portmap-protocol.pac portmap-analyzer.pac
    rpc-protocol.pac rpc-analyzer.pac
    smb-protocol.pac smb-mailslot.pac smb-pipe.pac
    ssl.pac ssl-analyzer.pac ssl-defs.pac
    ssl-protocol.pac ssl-record-layer.pac
)

foreach(binpact ${BINPAC_SRCS})
    binpac_target(${CMAKE_CURRENT_SOURCE_DIR}/${binpact})
endforeach(binpact)

########### next target ###############

set(dns_SRCS nb_dns.c nb_dns.h)

set(openssl_SRCS X509.cc SSLCiphers.cc SSLInterpreter.cc SSLProxy.cc
                 SSLv2.cc SSLv3.cc SSLv3Automaton.cc)

if (USE_NMALLOC)
    set(malloc_SRCS malloc.c)
endif ()

find_program(PERL_EXE perl)
if (NOT PERL_EXE)
    message(FATAL_ERROR "perl required")
endif ()

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdConstants.h
                          ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdInfoConstants.h
                   COMMAND ${PERL_EXE}
                   ARGS ${CMAKE_CURRENT_SOURCE_DIR}/make_dbg_constants.pl
                        ${CMAKE_CURRENT_SOURCE_DIR}/DebugCmdInfoConstants.in
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/DebugCmdInfoConstants.in
                   COMMENT "[Perl] Processing debug commands"
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(make_dbg_constants DEPENDS
                    ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdConstants.h
                    ${CMAKE_CURRENT_BINARY_DIR}/DebugCmdInfoConstants.h)

set(bro_SRCS
    ${BINPAC_AUXSRC}
    ${BINPAC_RPC_AUXSRC}
    ${ALL_BIF_OUTPUTS}
    ${ALL_BINPAC_OUTPUTS}
    ${CMAKE_CURRENT_BINARY_DIR}/version.c
    rule-parse.cc
    rule-parse.h
    ${FLEX_RuleScanner_OUTPUTS}
    re-parse.cc
    ${FLEX_REScanner_OUTPUTS}
    parse.cc
    ${FLEX_Scanner_OUTPUTS}
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
    PktDagSrc.cc
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

add_definitions(-DPOLICYDEST="${DATADIR}/bro/")

add_executable(bro ${bro_SRCS})

add_dependencies(bro make_dbg_constants)

target_link_libraries(bro
                      m
                      binpac_lib
                      ${PCAP_LIBRARY}
                      ${OPENSSL_LIBRARIES}
                      ${BIND_LIBRARY}
)

install(TARGETS bro DESTINATION bin)
