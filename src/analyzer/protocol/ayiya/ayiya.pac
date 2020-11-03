
%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/TunnelEncapsulation.h"
%}

analyzer AYIYA withcontext {
	connection:	AYIYA_Conn;
	flow:		AYIYA_Flow;
};

%include ayiya-protocol.pac
%include ayiya-analyzer.pac
