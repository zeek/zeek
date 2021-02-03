%include binpac.pac
%include zeek.pac

%extern{
	#include "zeek/analyzer/protocol/rdp/events.bif.h"
%}

analyzer RDPEUDP withcontext {
	connection: RDPEUDP_Conn;
	flow:       RDPEUDP_Flow;
};

connection RDPEUDP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = RDPEUDP_Flow(true);
	downflow = RDPEUDP_Flow(false);
};

%include rdpeudp-protocol.pac

flow RDPEUDP_Flow(is_orig: bool) {
	datagram = RDPEUDP_PDU(is_orig) withcontext(connection, this);
};

%include rdpeudp-analyzer.pac
