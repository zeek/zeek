# $Id:$

%include bro.pac

analyzer DHCP withcontext {
	connection:	DHCP_Conn;
	flow:		DHCP_Flow;
};

%include dhcp-protocol.pac
%include dhcp-analyzer.pac
