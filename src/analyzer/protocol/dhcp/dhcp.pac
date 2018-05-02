%include binpac.pac
%include bro.pac

%extern{
#include "types.bif.h"
#include "events.bif.h"
%}

analyzer DHCP withcontext {
	connection:	DHCP_Conn;
	flow:		DHCP_Flow;
};

connection DHCP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DHCP_Flow(true);
	downflow = DHCP_Flow(false);
};

flow DHCP_Flow(is_orig: bool) {
	datagram = DHCP_Message(is_orig) withcontext(connection, this);
};

%include dhcp-protocol.pac
%include dhcp-analyzer.pac
%include dhcp-options.pac
