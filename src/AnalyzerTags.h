#ifndef ANALYZERTAGS_H
#define ANALYZERTAGS_H

// Each kind of analyzer gets a tag consisting of a main type and subtype.
// The former determines the analyzer class to be instantiated, per the table
// in Analyzers.cc. The latter is passed through to that new analyzer
// instance and allows it to branch out to one out of a set of analyzers
// internally. The traditional, hard-coded analyzers don't use the subtype
// further, but the BinPAC++ support maps it to its analyzer definitions.
//
// When adding a new main type here, don't forget to adapt the table of
// analyzers in Analyzer.cc.

#include "config.h"
#include "util.h"

typedef uint32 AnalyzerID;

class AnalyzerTag  {
public:
	enum MainType {
		Error = 0,

		// Analyzer in charge of protocol detection.
		PIA_TCP, PIA_UDP,

		// Transport-layer analyzers.
		ICMP, TCP, UDP,

		// Application-layer analyzers (hand-written).
		BitTorrent, BitTorrentTracker,
		DCE_RPC, DNS, Finger, FTP, Gnutella, HTTP, Ident, IRC,
		Login, NCP, NetbiosSSN, NFS, NTP, POP3, Portmapper, Rlogin,
		RPC, Rsh, SMB, SMTP, SSH,
		Telnet,

		// Application-layer analyzers, binpac-generated.
		DHCP_BINPAC, DNS_TCP_BINPAC, DNS_UDP_BINPAC,
		HTTP_BINPAC, SSL, SYSLOG_BINPAC,
		Modbus,

		// Decapsulation analyzers.
		AYIYA,
		SOCKS,
		Teredo,
		GTPv1,

		// Other
		File, Backdoor, InterConn, SteppingStone, TCPStats,
		ConnSize,

		// Support-analyzers
		Contents, ContentLine, NVT, Zip, Contents_DNS, Contents_NCP,
		Contents_NetbiosSSN, Contents_Rlogin, Contents_Rsh,
		Contents_DCE_RPC, Contents_SMB, Contents_RPC, Contents_NFS,
		FTP_ADAT,

#ifdef HAVE_HILTI
		// BinPAC++ analyzer. These are different: each handles a set
		// of protocols, between we differentiate by subtype.
		PAC2_TCP, PAC2_UDP,
#endif

		EndOfAnalyzers,	// used as error code and array end marker.
	};

	AnalyzerTag(MainType arg_type = Error, uint32_t arg_subtype = 0)
		{ type = arg_type; subtype = arg_subtype; }

	AnalyzerTag(const AnalyzerTag& other)
		{ type = other.type; subtype = other.subtype; }

	AnalyzerTag(uint64_t tid)
		{ type = (MainType)(tid & 0xffffffffffffffff); subtype = (tid >> 32); }

	MainType Type() const 	{ return type; }
	uint32_t Subtype() const 	{ return subtype; }

	// Returns an identifying for this tag integer that's guaranteed to
	// be unique across all tags.
	operator uint64_t() const { return (uint64_t)(type) | ((uint64_t)subtype << 32); }

	bool operator==(const AnalyzerTag& other) const	{ return type == other.type && subtype == other.subtype; }
	bool operator!=(const AnalyzerTag& other) const	{ return type != other.type || subtype != other.subtype; }
	bool operator<(const AnalyzerTag& other) const
		{
		return type != other.type ? type < other.type : (subtype < other.subtype);
		}

	bool operator==(MainType arg_type) const	{ return type == arg_type; }
	bool operator!=(MainType arg_type) const	{ return type != arg_type; }

private:
	MainType type;
	uint32_t subtype; // Assigned by analyzer.
};

#endif
