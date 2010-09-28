# $Id:$

%include binpac.pac
%include bro.pac

analyzer HTTP withcontext {
	connection:	HTTP_Conn;
	flow:		HTTP_Flow;
};

%include http-protocol.pac
%include http-analyzer.pac
