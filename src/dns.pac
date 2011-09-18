%include bro.pac

analyzer DNS withcontext {
	connection:	DNS_Conn;
	flow:		DNS_Flow;
};

%include dns-protocol.pac
%include dns-analyzer.pac
