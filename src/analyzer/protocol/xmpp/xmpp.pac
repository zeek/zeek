# binpac file for the XMPP analyzer.
# Note that we currently do not even try to parse the protocol
# completely -- this is only supposed to be able to parse xmpp
# till StartTLS does (or does not) kick in.

%include binpac.pac
%include zeek.pac


%extern{

namespace zeek::analyzer::xmpp { class XMPP_Analyzer; }
namespace binpac { namespace XMPP { class XMPP_Conn; } }
using XMPPAnalyzer = zeek::analyzer::xmpp::XMPP_Analyzer*;

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/xmpp/XMPP.h"

#include "zeek/analyzer/protocol/xmpp/events.bif.h"
%}

extern type XMPPAnalyzer;

analyzer XMPP withcontext {
	connection:	 XMPP_Conn;
	flow:		 XMPP_Flow;
};

connection XMPP_Conn(zeek_analyzer: XMPPAnalyzer) {
	upflow = XMPP_Flow(true);
	downflow = XMPP_Flow(false);
};

%include xmpp-protocol.pac

flow XMPP_Flow(is_orig: bool) {
	datagram = XMPP_PDU(is_orig) withcontext(connection, this);
};

%include xmpp-analyzer.pac
