# Analyzer for Parser for rfb (VNC)
#  - rfb-protocol.pac: describes the rfb protocol messages
#  - rfb-analyzer.pac: describes the rfb analyzer code

%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer RFB withcontext {
	connection: RFB_Conn;
	flow:       RFB_Flow;
};

# Our connection consists of two flows, one in each direction.
connection RFB_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = RFB_Flow(true);
	downflow = RFB_Flow(false);
};

%include rfb-protocol.pac

# Now we define the flow:
flow RFB_Flow(is_orig: bool) {
	datagram = RFB_PDU(is_orig) withcontext(connection, this);
};

%include rfb-analyzer.pac