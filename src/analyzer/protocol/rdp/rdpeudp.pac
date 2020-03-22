%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"

	namespace analyzer { namespace rdpeudp { class RDPEUDP_Analyzer; } }
	typedef analyzer::rdpeudp::RDPEUDP_Analyzer* RDPEUDPAnalyzer;

	#include "RDPEUDP.h"
%}

extern type RDPEUDPAnalyzer;

analyzer RDPEUDP withcontext {
	connection: RDPEUDP_Conn;
	flow:       RDPEUDP_Flow;
};

# Our connection consists of two flows, one in each direction.
connection RDPEUDP_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = RDPEUDP_Flow(true);
	downflow = RDPEUDP_Flow(false);
};

%include rdpeudp-protocol.pac

flow RDPEUDP_Flow(is_orig: bool) {
	datagram = RDPEUDPPDU(is_orig) withcontext(connection, this);
};

%include rdpeudp-analyzer.pac
