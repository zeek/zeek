%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer RDPEUDP withcontext {
	connection: RDPEUDP_Conn;
	flow:       RDPEUDP_Flow;
};

connection RDPEUDP_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = RDPEUDP_Flow(true);
	downflow = RDPEUDP_Flow(false);
};

%include rdpeudp-protocol.pac

flow RDPEUDP_Flow(is_orig: bool) {
	datagram = RDPEUDP_PDU(is_orig) withcontext(connection, this);
};

%include rdpeudp-analyzer.pac
