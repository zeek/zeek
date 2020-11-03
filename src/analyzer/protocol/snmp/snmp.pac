%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/Reporter.h"
#include "types.bif.h"
#include "events.bif.h"
%}

analyzer SNMP withcontext {
	connection: SNMP_Conn;
	flow:       SNMP_Flow;
};

connection SNMP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = SNMP_Flow(true);
	downflow = SNMP_Flow(false);
};

%include snmp-protocol.pac

flow SNMP_Flow(is_orig: bool) {
	datagram = TopLevelMessage(is_orig) withcontext(connection, this);
};

%include snmp-analyzer.pac
