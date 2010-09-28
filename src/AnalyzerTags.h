// $Id: AnalyzerTags.h,v 1.1.2.5 2006/06/01 01:55:42 sommer Exp $

#ifndef ANALYZERTAGS_H
#define ANALYZERTAGS_H

// Each kind of analyzer gets a tag. When adding an analyzer here, also adapt
// the table of analyzers in Analyzer.cc.
//
// Using a namespace here is kind of a hack: ideally this would be in "class
// Analyzer {...}". But then we'd have circular dependencies across the header
// files.

#include "util.h"

typedef uint32 AnalyzerID;

namespace AnalyzerTag {
	enum Tag {
		Error = 0,	// used as error code

		// Analyzer in charge of protocol detection.
		PIA_TCP, PIA_UDP,

		// Transport-layer analyzers.
		ICMP, ICMP_TimeExceeded, ICMP_Unreachable, ICMP_Echo, TCP, UDP,

		// Application-layer analyzers (hand-written).
		BitTorrent, BitTorrentTracker,
		DCE_RPC, DNS, Finger, FTP, Gnutella, HTTP, Ident, IRC,
		Login, NCP, NetbiosSSN, NFS, NTP, POP3, Portmapper, Rlogin,
		RPC, Rsh, SMB, SMTP, SSH,
#ifdef USE_OPENSSL
		SSL,
#endif
		Telnet,

		// Application-layer analyzers, binpac-generated.
		DHCP_BINPAC, DNS_TCP_BINPAC, DNS_UDP_BINPAC,
		HTTP_BINPAC, RPC_UDP_BINPAC, SSL_BINPAC,

		// Other
		File, Backdoor, InterConn, SteppingStone, TCPStats,

		// Support-analyzers
		Contents, ContentLine, NVT, Zip, Contents_DNS, Contents_NCP,
		Contents_NetbiosSSN, Contents_Rlogin, Contents_Rsh,
		Contents_DCE_RPC, Contents_SMB, Contents_RPC, Contents_NFS,
#ifdef USE_OPENSSL
		Contents_SSL,
#endif
		// End-marker.
		LastAnalyzer
	};
};

#endif
