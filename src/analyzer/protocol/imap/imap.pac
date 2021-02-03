# binpac file for the IMAP analyzer.
# Note that we currently do not even try to parse the protocol
# completely -- this is only supposed to be able to parse imap
# till StartTLS does (or does not) kick in.

%include binpac.pac
%include zeek.pac

%extern{

namespace zeek::analyzer::imap { class IMAP_Analyzer; }
namespace binpac { namespace IMAP { class IMAP_Conn; } }
using IMAPAnalyzer = zeek::analyzer::imap::IMAP_Analyzer*;

#include "zeek/zeek-config.h"
#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/imap/IMAP.h"

#include "zeek/analyzer/protocol/imap/events.bif.h"

%}

extern type IMAPAnalyzer;

analyzer IMAP withcontext {
	connection:	 IMAP_Conn;
	flow:		 IMAP_Flow;
};

connection IMAP_Conn(zeek_analyzer: IMAPAnalyzer) {
	upflow = IMAP_Flow(true);
	downflow = IMAP_Flow(false);
};

%include imap-protocol.pac

flow IMAP_Flow(is_orig: bool) {
	datagram = IMAP_PDU(is_orig) withcontext(connection, this);
};

%include imap-analyzer.pac
