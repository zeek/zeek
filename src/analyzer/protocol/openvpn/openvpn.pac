# binpac file for SSL analyzer

%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"

namespace analyzer { namespace openvpn { class OpenVPN_Analyzer; } }
typedef analyzer::openvpn::OpenVPN_Analyzer* OpenVPNAnalyzer;

#include "OpenVPN.h"
%}

extern type OpenVPNAnalyzer;

analyzer openvpn withcontext {
	connection: OpenVPN_Conn;
	flow:       OpenVPN_Flow;
};

connection OpenVPN_Conn(bro_analyzer: OpenVPNAnalyzer) {
	upflow = OpenVPN_Flow(true);
	downflow = OpenVPN_Flow(false);
};

%include openvpn-protocol.pac

flow OpenVPN_Flow(is_orig: bool) {
  datagram = OpenVPNPDU(is_orig) withcontext(connection, this);
}

# %include openvpn-analyzer.pac
