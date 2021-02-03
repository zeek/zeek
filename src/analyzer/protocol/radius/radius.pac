# Analyzer for RADIUS
#  - radius-protocol.pac: describes the RADIUS protocol messages
#  - radius-analyzer.pac: describes the RADIUS analyzer code

%include binpac.pac
%include zeek.pac

%extern{
	#include "zeek/analyzer/protocol/radius/events.bif.h"
%}

analyzer RADIUS withcontext {
	connection: RADIUS_Conn;
	flow:       RADIUS_Flow;
};

# Our connection consists of two flows, one in each direction.
connection RADIUS_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = RADIUS_Flow(true);
	downflow = RADIUS_Flow(false);
};

%include radius-protocol.pac

# Now we define the flow:
flow RADIUS_Flow(is_orig: bool) {
	datagram = RADIUS_PDU(is_orig) withcontext(connection, this);
};

%include radius-analyzer.pac
