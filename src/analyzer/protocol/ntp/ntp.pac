
%include binpac.pac
%include zeek.pac

%extern{
	#include "zeek/analyzer/protocol/ntp/types.bif.h"
	#include "zeek/analyzer/protocol/ntp/events.bif.h"
%}

analyzer NTP withcontext {
	connection: NTP_Conn;
	flow:       NTP_Flow;
};

connection NTP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = NTP_Flow(true);
	downflow = NTP_Flow(false);
};

%include ntp-mode7.pac
%include ntp-protocol.pac

flow NTP_Flow(is_orig: bool) {
	datagram = NTP_PDU(is_orig) withcontext(connection, this);
};

%include ntp-analyzer.pac
