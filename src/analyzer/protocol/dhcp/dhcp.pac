%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer DHCP withcontext {
	connection:	DHCP_Conn;
	flow:		DHCP_Flow;
};

%include dhcp-protocol.pac
%include dhcp-analyzer.pac
