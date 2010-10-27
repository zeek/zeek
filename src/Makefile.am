## Process this file with automake to produce Makefile.in
#
#  Copyright (c) 1997-2005
#	The Regents of the University of California.  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that: (1) source code distributions
#  retain the above copyright notice and this paragraph in its entirety, (2)
#  distributions including binary code include the above copyright notice and
#  this paragraph in its entirety in the documentation or other materials
#  provided with the distribution, and (3) all advertising materials mentioning
#  features or use of this software display the following acknowledgement:
#  ``This product includes software developed by the University of California,
#  Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
#  the University nor the names of its contributors may be used to endorse
#  or promote products derived from this software without specific prior
#  written permission.
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
#  $Id: Makefile.am 6588 2009-02-17 00:02:53Z vern $
#
#

noinst_PROGRAMS = bifcl
bin_PROGRAMS = bro

bifcl_SOURCES = bif_lex.cc bif_parse.cc bif_arg.cc

BINPAC_SRC = binpac-lib.pac binpac_bro-lib.pac bittorrent.pac \
	dce_rpc.pac dce_rpc_simple.pac dhcp.pac dns.pac \
	dns_tcp.pac http.pac ncp.pac netflow.pac rpc.pac smb.pac \
	ssl.pac ssl-record-layer.pac syslog.pac

BINPAC_H = $(BINPAC_SRC:.pac=_pac.h)
BINPAC_CC = $(BINPAC_SRC:.pac=_pac.cc)
BINPAC_AUXSRC = binpac.pac bro.pac binpac_bro.h

BINPAC_RPC_AUXSRC = \
	bittorrent-protocol.pac bittorrent-analyzer.pac \
	dce_rpc-analyzer.pac dce_rpc-protocol.pac \
	dhcp-analyzer.pac dhcp-protocol.pac \
	dns-analyzer.pac dns-protocol.pac \
	epmapper.pac \
	http-analyzer.pac http-protocol.pac http.pac \
	netflow-protocol.pac netflow-analyzer.pac \
	portmap-protocol.pac portmap-analyzer.pac \
	rpc-protocol.pac rpc-analyzer.pac \
	smb-protocol.pac smb-mailslot.pac smb-pipe.pac \
	ssl.pac ssl-analyzer.pac ssl-defs.pac \
	ssl-protocol.pac ssl-record-layer.pac \
	syslog.pac syslog-protocol.pac syslog-analyzer.pac

BINPAC = @BINPAC@
BINPAC_FLAGS = -d $(top_builddir)/src -I $(srcdir)
LIBBINPAC = $(top_builddir)/aux/binpac/lib/libbinpac.a
LIBBINPAC_LIBS = -L$(top_builddir)/aux/binpac/lib -lbinpac

# File locking helper to synchronize targets in parallel builds
LOCK_FILE = $(top_builddir)/aux/scripts/lock_file

# List all optionally built source files here.
EXTRA_bro_SOURCES = X509.cc SSLCiphers.cc SSLInterpreter.cc SSLProxy.cc \
	SSLv2.cc SSLv3.cc SSLv3Automaton.cc nb_dns.c malloc.c

if USE_NBDNS
dns_srcs = nb_dns.c
endif

if USE_OPENSSL
openssl_srcs = X509.cc SSLCiphers.cc SSLInterpreter.cc SSLProxy.cc \
	SSLv2.cc SSLv3.cc SSLv3Automaton.cc
endif

# this is much faster on FreeBSD
if USE_NMALLOC
malloc_srcs = malloc.c
endif

# Forces libedit, bifcl and all generated files to be done first.
# NOTE: Order does matter here, bifcl needs to be before the generated files
# to be correct, the generated files should depend on bifcl, but this causes
# the whole tree to be rebuilt in some cases.
#
# Binpac handling: the main .pac files are explicitly listed in BINPAC_SRC,
# with implicit lists for the corresponding _pac.cc/_pac.h files. We do not
# list the _pac.cc files in bro_SOURCES, since then they'd become part of
# DISTFILES and distcheck would try to build them before binpac exists.
# (This would still work on a previously built tree, but not on a fresh
# checkout.)  To mark the _pac.cc/_pac.h files as sources and ensure the
# resulting object files are linked in, we use nodist_bro_SOURCES. Finally,
# to ensure they're built first, we also list the _pac.cc files in
# BUILT_SOURCES. --cpk
#
BUILT_SOURCES = bifcl $(BIF_FUNC_H) \
	DebugCmdInfoConstants.cc DebugCmdConstants.h \
	$(BINPAC_CC)

EXTRA_DIST = $(BIFS) SMB_COM.def SMTP_cmd.def \
	POP3_cmd.def bif_type.def builtin-func.y parse.y re-parse.y rule-parse.y \
	make_parser.pl make_dbg_constants.pl parse.in scan.l \
	re-scan.l rule-scan.l builtin-func.l DebugCmdInfoConstants.in \
	$(BINPAC_SRC) $(BINPAC_AUXSRC) $(BINPAC_RPC_AUXSRC)

nodist_bro_SOURCES = $(BINPAC_CC) $(BINPAC_H)

bro_SOURCES = \
	main.cc net_util.cc util.cc \
	parse.cc scan.cc re-parse.cc re-scan.cc rule-parse.cc rule-scan.cc \
	Active.cc Analyzer.cc Anon.cc ARP.cc Attr.cc \
	BackDoor.cc Base64.cc BitTorrent.cc BitTorrentTracker.cc \
	BPF_Program.cc BroString.cc \
	CCL.cc ChunkedIO.cc CompHash.cc Conn.cc ConnCompressor.cc \
	ContentLine.cc DCE_RPC.cc DFA.cc \
	DHCP-binpac.cc DNS.cc DNS-binpac.cc DNS_Mgr.cc \
	DbgBreakpoint.cc DbgHelp.cc DbgWatch.cc Debug.cc \
	DebugCmds.cc DebugLogger.cc Desc.cc Dict.cc Discard.cc DPM.cc \
	EquivClass.cc Event.cc EventHandler.cc EventLauncher.cc \
	EventRegistry.cc \
	Expr.cc FTP.cc File.cc FileAnalyzer.cc Finger.cc FlowSrc.cc Frag.cc \
	Frame.cc Func.cc Gnutella.cc HTTP.cc HTTP-binpac.cc Hash.cc ICMP.cc \
	ID.cc Ident.cc IntSet.cc InterConn.cc IOSource.cc IRC.cc \
	List.cc Logger.cc Login.cc MIME.cc \
	NCP.cc NFA.cc NFS.cc NTP.cc NVT.cc Net.cc NetVar.cc \
	NetbiosSSN.cc Obj.cc OSFinger.cc \
	PacketFilter.cc PacketSort.cc PersistenceSerializer.cc \
	PktDagSrc.cc PktSrc.cc PIA.cc \
	PolicyFile.cc POP3.cc Portmap.cc PrefixTable.cc PriorityQueue.cc \
	Queue.cc RE.cc RPC.cc Reassem.cc RemoteSerializer.cc Rlogin.cc RSH.cc \
	Rule.cc RuleAction.cc RuleCondition.cc RuleMatcher.cc \
	ScriptAnaly.cc SmithWaterman.cc SMB.cc SMTP.cc \
	SSH.cc SSL-binpac.cc Syslog-binpac.cc \
	Scope.cc SerializationFormat.cc SerialObj.cc Serializer.cc \
	Sessions.cc StateAccess.cc Stats.cc SteppingStone.cc Stmt.cc \
	TCP.cc TCP_Endpoint.cc TCP_Reassembler.cc TCP_Rewriter.cc \
	Telnet.cc Timer.cc Traverse.cc Trigger.cc TwoWise.cc Type.cc UDP.cc \
	Val.cc Var.cc XDR.cc ZIP.cc \
	bsd-getopt-long.c cq.c md5.c patricia.c setsignal.c version.c \
	UDP_Rewriter.cc DNS_Rewriter.cc PacketDumper.cc Rewriter.cc \
	strsep.c $(dns_srcs) $(malloc_srcs) $(openssl_srcs)

noinst_HEADERS = Active.h Analyzer.h AnalyzerTags.h Anon.h ARP.h Attr.h \
	BPF_Program.h BackDoor.h Base64.h BitTorrent.h BitTorrentTracker.h \
	BroList.h BroString.h \
	CCL.h ChunkedIO.h CompHash.h Conn.h ConnCompressor.h ContentLine.h \
	Continuation.h DCE_RPC.h DFA.h \
	DHCP-binpac.h DNS.h DNS-binpac.h DNS_Mgr.h \
	DbgBreakpoint.h DbgDisplay.h DbgWatch.h Debug.h \
	DebugCmds.h DebugLogger.h Desc.h Dict.h DPM.h \
	Discard.h EquivClass.h Event.h EventHandler.h EventLauncher.h \
	EventRegistry.h Expr.h FTP.h File.h FileAnalyzer.h \
	Finger.h FlowSrc.h Frag.h Frame.h Func.h Gnutella.h \
	H3.h HTTP.h HTTP-binpac.h Hash.h ICMP.h ID.h IP.h Ident.h \
	IntSet.h InterConn.h IOSource.h IRC.h List.h Logger.h \
	Login.h MIME.h NCP.h NFA.h NFS.h NTP.h NVT.h Net.h NetVar.h \
	NetbiosSSN.h Obj.h OSFinger.h Op.h \
	PacketFilter.h PacketSort.h PersistenceSerializer.h \
	PktDagSrc.h PktSrc.h PIA.h \
	PolicyFile.h POP3.h Portmap.h PrefixTable.h PriorityQueue.h \
	Queue.h RE.h \
	RPC.h Reassem.h RemoteSerializer.h Rlogin.h RSH.h Rule.h RuleAction.h \
	RuleCondition.h RuleMatcher.h \
	ScriptAnaly.h SmithWaterman.h SMB.h SMTP.h \
	SSL-binpac.h SSH.h SSLCiphers.h SSLDefines.h \
	SSLInterpreter.h SSLProxy.h SSLv2.h SSLv3.h SSLv3Automaton.h Scope.h \
	SerialInfo.h SerialObj.h SerialTypes.h \
	SerializationFormat.h Serializer.h Sessions.h StateAccess.h \
	Stats.h SteppingStone.h Stmt.h StmtEnums.h Syslog-binpac.h \
	TCP.h TCP_Endpoint.h TCP_Reassembler.h TCP_Rewriter.h Telnet.h Timer.h \
	Traverse.h TraverseTypes.h Trigger.h TwoWise.h Type.h UDP.h \
	Val.h Var.h X509.h XDR.h ZIP.h \
	bif_arg.h bif_parse.h broparse.h bsd-getopt-long.h cq.h input.h md5.h \
	nb_dns.h net_util.h patricia.h re-parse.h rule-parse.h \
	UDP_Rewriter.h DNS_Rewriter.h PacketDumper.h Rewriter.h \
	setsignal.h util.h

bro_LDADD = $(LIBIDMEF_LIBS) @LIBS@ -lm $(LIBBINPAC_LIBS)

# Files we generate locally that need to be removed with make distclean,
# mostly to keep distcheck happy.
# 
DISTCLEANFILES = DebugCmdInfoConstants.cc DebugCmdConstants.h \
	DebugCmdConstants.cc DebugCmdConstants.h \
	$(BINPAC_CC) $(BINPAC_H) $(BIF_BRO) y.output bif_lex.cc \
	bif_parse.h bif_parse.cc parse.y scan.cc parse.cc broparse.h \
	re-parse.cc re-parse.h re-scan.cc rule-parse.cc rule-parse.h \
	rule-scan.cc version.c

# Files created in the src dir.
MOSTLYCLEANFILES = $(BIF_FUNC_H) $(BIF_FUNC_DEF) $(BIF_FUNC_INIT) \
		   $(BIF_NETVAR_H) $(BIF_NETVAR_DEF) $(BIF_NETVAR_INIT) \
		   $(BRO_BIF) \
		   $(BINPAC_H) $(BINPAC_CC) \
		   $(DISTCLEANFILES)

POLICYDEST=${datadir}/bro

CCOPT = @V_CCOPT@ -W -Wall -Wno-unused
INCLS = @V_INCLS@

YFLAGS = -d -t -v

# Should use AM_ vars, but automake 1.5 errors out.
#AM_LDFLAGS = @LDFLAGS@ 
LDFLAGS = @LDFLAGS@

#AM_CFLAGS = -I. -I.. -I$(top_srcdir)/src -I$(srcdir) -I$(top_builddir)
AM_CFLAGS = -I. -I$(top_srcdir)/aux/binpac/lib -I$(top_srcdir)/src -I$(srcdir) -I$(top_builddir)

#AM_CPPFLAGS = $(AM_CFLAGS) $(LIBIDMEF_INCL) $(INCLS) $(CCOPT) -I/usr/include
AM_CPPFLAGS = $(AM_CFLAGS) $(LIBIDMEF_INCL) $(INCLS) $(CCOPT)

BIFCL = ./bifcl
BIFS =	bro.bif event.bif const.bif \
	common-rw.bif finger-rw.bif ident-rw.bif \
	dns-rw.bif ftp-rw.bif smtp-rw.bif http-rw.bif strings.bif \
	smb-rw.bif

BIF_FUNC_H = $(BIFS:.bif=.bif.func_h)
BIF_FUNC_DEF = $(BIFS:.bif=.bif.func_def)
BIF_FUNC_INIT = $(BIFS:.bif=.bif.func_init)
BIF_NETVAR_H = $(BIFS:.bif=.bif.netvar_h)
BIF_NETVAR_DEF = $(BIFS:.bif=.bif.netvar_def)
BIF_NETVAR_INIT = $(BIFS:.bif=.bif.netvar_init)

BIF_BRO = $(BIFS:.bif=.bif.bro)


BIFOBJ = bif_arg.o bif_lex.o bif_parse.o
BIFCLEAN = bifcl $(BIFOBJ) $(BIF_FUNC_DEF) $(BIF_NETVAR_DEF) policy/*.bif.bro

PRIV = priv

opt:
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/-O2//;s/$$/ -O3/'`"

debug: 
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/-O2/-O0/g;s/$$/ -g -Wall -DDEBUG/'`"

profile:
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/$$/ -O0 -pg/'`" LDFLAGS="`echo $(LDFLAGS) | sed -e 's/$$/ -pg/'`"

mpatrol:
	@$(MAKE) $(MFLAGS) LIBS="`echo $(LIBS) | sed -e 's/$$/ -lmpatrol/'`"

version.c: $(top_srcdir)/VERSION
	@rm -f $@
	sed -e 's/.*/char version[] = "&";/' $(top_srcdir)/VERSION > $@

DebugCmdInfoConstants.cc DebugCmdInfoConstants.h: DebugCmdInfoConstants.in
	perl $(srcdir)/make_dbg_constants.pl $(srcdir)/DebugCmdInfoConstants.in

DebugCmdConstants.cc DebugCmdConstants.h: DebugCmdInfoConstants.in
	perl $(srcdir)/make_dbg_constants.pl $(srcdir)/DebugCmdInfoConstants.in

# Should these be moved to $(destdir)/policy?
finger-rw.bif.func_h finger-rw.bif.func_def finger-rw.bif.func_init: finger-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/finger-rw.bif
	@cp finger-rw.bif.bro ../policy/

ftp-rw.bif.func_h ftp-rw.bif.func_def ftp-rw.bif.func_init: ftp-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/ftp-rw.bif
	@cp ftp-rw.bif.bro ../policy/

smb-rw.bif.func_h smb-rw.bif.func_def smb-rw.bif.func_init: smb-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/smb-rw.bif
	@cp smb-rw.bif.bro ../policy/

dns-rw.bif.func_h dns-rw.bif.func_def dns-rw.bif.func_init: dns-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/dns-rw.bif
	@cp dns-rw.bif.bro ../policy/

bro.bif.func_h bro.bif.func_def bro.bif.func_init: bro.bif $(BIFCL)
	$(BIFCL) $(srcdir)/bro.bif
	@cp bro.bif.bro ../policy/

ident-rw.bif.func_h ident-rw.bif.func_def ident-rw.bif.func_init: ident-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/ident-rw.bif
	@cp ident-rw.bif.bro ../policy/

event.bif.func_h event.bif.netvar_h event.bif.netvar_def event.bif.netvar_init: event.bif $(BIFCL)
	$(BIFCL) $(srcdir)/event.bif
	@cp event.bif.bro ../policy/

const.bif.func_h const.bif.netvar_h const.bif.netvar_def const.bif.netvar_init: const.bif $(BIFCL)
	$(BIFCL) $(srcdir)/const.bif
	@cp const.bif.bro ../policy/

binpac-lib_pac.h binpac-lib_pac.cc: binpac-lib.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) $(LIBBINPAC)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/binpac-lib.pac

binpac_bro-lib_pac.h binpac_bro-lib_pac.cc: binpac_bro-lib.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/binpac_bro-lib.pac

bittorrent_pac.h bittorrent_pac.cc: bittorrent.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) bittorrent-protocol.pac bittorrent-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/bittorrent.pac

dce_rpc_pac.h dce_rpc_pac.cc: dce_rpc.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) dce_rpc-protocol.pac dce_rpc-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/dce_rpc.pac

dce_rpc_simple_pac.h dce_rpc_simple_pac.cc: dce_rpc_simple.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) dce_rpc-protocol.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/dce_rpc_simple.pac

dhcp_pac.h dhcp_pac.cc: dhcp.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) dhcp-protocol.pac dhcp-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/dhcp.pac

dns_pac.h dns_pac.cc: dns.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) dns-protocol.pac dns-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/dns.pac

dns_tcp_pac.h dns_tcp_pac.cc: dns_tcp.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/dns_tcp.pac

http_pac.h http_pac.cc: http.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) http-protocol.pac http-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/http.pac

ncp_pac.h ncp_pac.cc: ncp.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/ncp.pac

netflow_pac.h netflow_pac.cc: netflow.pac netflow-protocol.pac netflow-analyzer.pac Event.h $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/netflow.pac

rpc_pac.h rpc_pac.cc: rpc.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) $(BINPAC_RPC_AUXSRC)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/rpc.pac

smb_pac.h smb_pac.cc: smb.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) smb-protocol.pac smb-mailslot.pac smb-pipe.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/smb.pac

ssl_pac.h ssl_pac.cc: ssl.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) ssl-protocol.pac ssl-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/ssl.pac

ssl-record-layer_pac.h ssl-record-layer_pac.cc: ssl-record-layer.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR)
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/ssl-record-layer.pac

syslog_pac.h syslog_pac.cc: syslog.pac $(BINPAC) $(BINPAC_AUXSRC) $(BINPAC_AUXHDR) syslog-protocol.pac syslog-analyzer.pac
	$(BINPAC) $(BINPAC_FLAGS) $(srcdir)/syslog.pac


patricia.o: patricia.c patricia.h
	$(CC) $(CFLAGS) -c $(srcdir)/patricia.c

smtp-rw.bif.func_h smtp-rw.bif.func_def smtp-rw.bif.func_init: smtp-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/smtp-rw.bif
	@cp smtp-rw.bif.bro ../policy/

http-rw.bif.func_h http-rw.bif.func_def http-rw.bif.func_init: http-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/http-rw.bif
	@cp http-rw.bif.bro ../policy/

common-rw.bif.func_h common-rw.bif.func_def common-rw.bif.func_init: common-rw.bif $(BIFCL)
	$(BIFCL) $(srcdir)/common-rw.bif
	@cp common-rw.bif.bro ../policy/

strings.bif.func_h strings.bif.func_def strings.bif.func_init: strings.bif $(BIFCL)
	$(BIFCL) $(srcdir)/strings.bif
	@cp strings.bif.bro ../policy/

broparse.h parse.cc: parse.y
	$(LOCK_FILE) lock broparse || exit; \
	test -e broparse.h && ( $(LOCK_FILE) unlock broparse; exit 0; ); \
	$(YACC) $(YFLAGS) -o p.c parse.y; \
	sed '/extern char.*getenv/d;s/yylex/brolex/' <p.c >parse.cc; \
	mv p.h broparse.h; \
	rm p.c; \
	$(LOCK_FILE) unlock broparse

parse.y: parse.in make_parser.pl
	@rm -f parse.y
	perl -w $(srcdir)/make_parser.pl $(srcdir) $(top_builddir)/src "$(YACC)"
	chmod -w parse.y

scan.cc: scan.l broparse.h
	$(LEX) $(LFLAGS) -Pbro -oscan.cc $(srcdir)/scan.l

bif_lex.cc: builtin-func.l bif_parse.h
	$(LEX) -o$@ $(srcdir)/builtin-func.l

re-parse.h re-parse.cc: re-parse.y
	$(LOCK_FILE) lock reparse || exit; \
	test -e re-parse.h && ( $(LOCK_FILE) unlock reparse; exit 0; ); \
	$(YACC) $(YFLAGS) -o rep.c $(srcdir)/re-parse.y; \
	sed '/extern char.*getenv/d;s/yylex/re_lex/;s/yy/RE_/g' <rep.c >re-parse.cc; \
	mv rep.h re-parse.h; \
	rm rep.c; \
	$(LOCK_FILE) unlock reparse

re-scan.cc: re-scan.l
	$(LEX) $(LFLAGS) -Pre_ -ore-scan.cc $(srcdir)/re-scan.l

rule-parse.h rule-parse.cc: rule-parse.y
	$(LOCK_FILE) lock ruleparse || exit; \
	test -e rule-parse.h && ( $(LOCK_FILE) unlock ruleparse; exit 0; ); \
	$(YACC) $(YFLAGS) -o rup.c $(srcdir)/rule-parse.y; \
	sed '/extern char.*getenv/d;s/yylex/rules_lex/;s/yy/rules_/g' <rup.c >rule-parse.cc; \
	sed '/extern char.*getenv/d;s/yylex/rules_lex/;s/yy/rules_/g' <rup.h >rule-parse.h; \
	rm rup.c rup.h; \
	$(LOCK_FILE) unlock ruleparse

rule-scan.cc: rule-scan.l
	$(LEX) $(LFLAGS) -Prules_ -orule-scan.cc $(srcdir)/rule-scan.l

bif_parse.h bif_parse.cc: builtin-func.y bif_arg.h bif_type.def
	$(LOCK_FILE) lock bifparse || exit; \
	test -e bif_parse.h && ( $(LOCK_FILE) unlock bifparse; exit 0; ); \
	$(YACC) $(YFLAGS) -o bf.c $(top_srcdir)/src/builtin-func.y; \
	mv bf.h bif_parse.h; \
	mv bf.c bif_parse.cc; \
	$(LOCK_FILE) unlock bifparse

# Need this rule because of the POLICYDEST.
util.o: util.cc util.h
	$(CXX) $(AM_CPPFLAGS) -DPOLICYDEST=\"$(POLICYDEST)\" -c $(srcdir)/util.cc

CHANGES: $(top_srcdir)/VERSION
	@echo "You need to update CHANGES"
