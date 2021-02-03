# BinPAC file for SIP analyzer
# Based heavily on the HTTP BinPAC analyzer

%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/protocol/sip/events.bif.h"
%}

analyzer SIP withcontext {
	connection:	 SIP_Conn;
	flow:		 SIP_Flow;
};

connection SIP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = SIP_Flow(true);
	downflow = SIP_Flow(false);
};

%include sip-protocol.pac

flow SIP_Flow(is_orig: bool) {
	flowunit = SIP_PDU(is_orig) withcontext(connection, this);
};

%include sip-analyzer.pac
