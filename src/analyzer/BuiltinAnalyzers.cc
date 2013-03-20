
#include "BuiltInAnalyzers.h"
#include "PluginComponent.h"

#include "../binpac_bro.h"

#include "AYIYA.h"
#include "BackDoor.h"
#include "BitTorrent.h"
#include "BitTorrentTracker.h"
#include "Finger.h"
#include "InterConn.h"
#include "NTP.h"
#include "HTTP.h"
#include "HTTP-binpac.h"
#include "ICMP.h"
#include "SteppingStone.h"
#include "IRC.h"
#include "SMTP.h"
#include "FTP.h"
#include "FileAnalyzer.h"
#include "DNS.h"
#include "DNS-binpac.h"
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
#include "SSL.h"
#include "Syslog-binpac.h"
#include "Teredo.h"
#include "ConnSizeAnalyzer.h"
#include "GTPv1.h"

using namespace analyzer;

#define DEFINE_ANALYZER(name, factory, enabled, partial) \
	AddComponent(new PluginComponent(name, factory, enabled, partial))

void BuiltinAnalyzers::Init()
	{
	plugin::Description desc;
	desc.name = "Core-Analyzers";
	desc.description = "Built-in protocol analyzers";
	desc.version = plugin::API_BUILTIN;
	SetDescription(desc);

	DEFINE_ANALYZER("PIA_TCP", PIA_TCP::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("PIA_UDP", PIA_UDP::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("ICMP", ICMP_Analyzer::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("TCP", TCP_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("UDP", UDP_Analyzer::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("BITTORRENT", BitTorrent_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("BITTORRENTTRACKER", BitTorrentTracker_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("DCE_RPC", DCE_RPC_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("DNS", DNS_Analyzer::InstantiateAnalyzer, ! FLAGS_use_binpac, false);
	DEFINE_ANALYZER("FINGER", Finger_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("FTP", FTP_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("GNUTELLA", Gnutella_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("HTTP", HTTP_Analyzer::InstantiateAnalyzer, ! FLAGS_use_binpac, false);
	DEFINE_ANALYZER("IDENT", Ident_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("IRC", IRC_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("LOGIN", 0, true, false);  // just a base class
	DEFINE_ANALYZER("NCP", NCP_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("NETBIOSSSN", NetbiosSSN_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("NFS", NFS_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("NTP", NTP_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("POP3", POP3_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("PORTMAPPER", Portmapper_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("RLOGIN", Rlogin_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("RPC", 0, true, false);
	DEFINE_ANALYZER("RSH", Rsh_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("SMB", SMB_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("SMTP", SMTP_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("SSH", SSH_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("TELNET", Telnet_Analyzer::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("DHCP_BINPAC", DHCP_Analyzer_binpac::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("DNS_TCP_BINPAC", DNS_TCP_Analyzer_binpac::InstantiateAnalyzer, FLAGS_use_binpac, false);
	DEFINE_ANALYZER("DNS_UDP_BINPAC", DNS_UDP_Analyzer_binpac::InstantiateAnalyzer, FLAGS_use_binpac, false);
	DEFINE_ANALYZER("HTTP_BINPAC", HTTP_Analyzer_binpac::InstantiateAnalyzer, FLAGS_use_binpac, false);
	DEFINE_ANALYZER("SSL", SSL_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("SYSLOG_BINPAC", Syslog_Analyzer_binpac::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("MODBUS", ModbusTCP_Analyzer::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("AYIYA", AYIYA_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("SOCKS", SOCKS_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("TEREDO", Teredo_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("GTPV1", GTPv1_Analyzer::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("FILE", File_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("BACKDOOR", BackDoor_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("INTERCONN", InterConn_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("STEPPINGSTONE", SteppingStone_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("TCPSTATS", TCPStats_Analyzer::InstantiateAnalyzer, true, false);
	DEFINE_ANALYZER("CONNSIZE", ConnSize_Analyzer::InstantiateAnalyzer, true, false);

	DEFINE_ANALYZER("CONTENTS", 0, true, false);
	DEFINE_ANALYZER("CONTENTLINE", 0, true, false);
	DEFINE_ANALYZER("NVT", 0, true, false);
	DEFINE_ANALYZER("ZIP", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_DNS", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_NETBIOSSSN", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_NCP", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_RLOGIN", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_RSH", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_DCE_RPC", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_SMB", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_RPC", 0, true, false);
	DEFINE_ANALYZER("CONTENTS_NFS", 0, true, false);
	DEFINE_ANALYZER("FTP_ADAT", 0, true, false);
	}

