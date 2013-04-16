
// TODO: This file will eventually go away once we've converrted all
// analyzers into separate plugins.

#include "BuiltInAnalyzers.h"
#include "analyzer/Component.h"

#include "../../binpac_bro.h"

#include "AYIYA.h"
#include "BackDoor.h"
#include "BitTorrent.h"
#include "BitTorrentTracker.h"
#include "Finger.h"
#include "InterConn.h"
#include "NTP.h"
#include "ICMP.h"
#include "SteppingStone.h"
#include "IRC.h"
#include "SMTP.h"
#include "FTP.h"
#include "FileAnalyzer.h"
#include "DNS.h"
#include "DHCP-binpac.h"
#include "Telnet.h"
#include "Rlogin.h"
#include "RSH.h"
#include "DCE_RPC.h"
#include "Gnutella.h"
#include "Ident.h"
#include "Modbus.h"
#include "NCP.h"
#include "NetbiosSSN.h"
#include "SMB.h"
#include "NFS.h"
#include "Portmap.h"
#include "POP3.h"
#include "SOCKS.h"
#include "SSH.h"
#include "Teredo.h"
#include "ConnSizeAnalyzer.h"
#include "GTPv1.h"

using namespace analyzer;

BuiltinAnalyzers builtin_analyzers;

#define DEFINE_ANALYZER(name, factory) \
	AddComponent(new Component(name, factory))

void BuiltinAnalyzers::Init()
	{
	SetName("Core-Analyzers");
	SetDescription("Built-in protocol analyzers");
	SetVersion(BRO_PLUGIN_VERSION_BUILTIN);

	DEFINE_ANALYZER("PIA_TCP", PIA_TCP::InstantiateAnalyzer);
	DEFINE_ANALYZER("PIA_UDP", PIA_UDP::InstantiateAnalyzer);

	DEFINE_ANALYZER("ICMP", ICMP_Analyzer::InstantiateAnalyzer);

	DEFINE_ANALYZER("TCP", TCP_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("UDP", UDP_Analyzer::InstantiateAnalyzer);

	DEFINE_ANALYZER("BITTORRENT", BitTorrent_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("BITTORRENTTRACKER", BitTorrentTracker_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("DCE_RPC", DCE_RPC_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("DNS", DNS_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("FINGER", Finger_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("FTP", FTP_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("GNUTELLA", Gnutella_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("IDENT", Ident_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("IRC", IRC_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("LOGIN", 0);  // just a base class
	DEFINE_ANALYZER("NCP", NCP_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("NETBIOSSSN", NetbiosSSN_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("NFS", NFS_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("NTP", NTP_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("POP3", POP3_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("PORTMAPPER", Portmapper_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("RLOGIN", Rlogin_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("RPC", 0);
	DEFINE_ANALYZER("RSH", Rsh_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("SMB", SMB_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("SMTP", SMTP_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("SSH", SSH_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("TELNET", Telnet_Analyzer::InstantiateAnalyzer);

	DEFINE_ANALYZER("DHCP_BINPAC", DHCP_Analyzer_binpac::InstantiateAnalyzer);
	DEFINE_ANALYZER("MODBUS", ModbusTCP_Analyzer::InstantiateAnalyzer);

	DEFINE_ANALYZER("AYIYA", AYIYA_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("SOCKS", SOCKS_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("TEREDO", Teredo_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("GTPV1", GTPv1_Analyzer::InstantiateAnalyzer);

	DEFINE_ANALYZER("FILE", File_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("BACKDOOR", BackDoor_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("INTERCONN", InterConn_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("STEPPINGSTONE", SteppingStone_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("TCPSTATS", TCPStats_Analyzer::InstantiateAnalyzer);
	DEFINE_ANALYZER("CONNSIZE", ConnSize_Analyzer::InstantiateAnalyzer);

	DEFINE_ANALYZER("CONTENTS", 0);
	DEFINE_ANALYZER("CONTENTLINE", 0);
	DEFINE_ANALYZER("NVT", 0);
	DEFINE_ANALYZER("ZIP", 0);
	DEFINE_ANALYZER("CONTENTS_DNS", 0);
	DEFINE_ANALYZER("CONTENTS_NETBIOSSSN", 0);
	DEFINE_ANALYZER("CONTENTS_NCP", 0);
	DEFINE_ANALYZER("CONTENTS_RLOGIN", 0);
	DEFINE_ANALYZER("CONTENTS_RSH", 0);
	DEFINE_ANALYZER("CONTENTS_DCE_RPC", 0);
	DEFINE_ANALYZER("CONTENTS_SMB", 0);
	DEFINE_ANALYZER("CONTENTS_RPC", 0);
	DEFINE_ANALYZER("CONTENTS_NFS", 0);
	DEFINE_ANALYZER("FTP_ADAT", 0);
	}

