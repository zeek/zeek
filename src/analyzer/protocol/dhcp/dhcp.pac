%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/protocol/dhcp/types.bif.h"
#include "zeek/analyzer/protocol/dhcp/events.bif.h"
%}

analyzer DHCP withcontext {
	connection:	DHCP_Conn;
	flow:		DHCP_Flow;
};

connection DHCP_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = DHCP_Flow(true);
	downflow = DHCP_Flow(false);
};

flow DHCP_Flow(is_orig: bool) {
	datagram = DHCP_Message(is_orig) withcontext(connection, this);
};

%include dhcp-protocol.pac
%include dhcp-analyzer.pac
%include dhcp-options.pac
