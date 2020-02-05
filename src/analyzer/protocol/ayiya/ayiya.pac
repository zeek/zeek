
%include binpac.pac
%include bro.pac

%extern{
#include "IP.h"
#include "Reporter.h"
#include "TunnelEncapsulation.h"
%}

analyzer AYIYA withcontext {
	connection:	AYIYA_Conn;
	flow:		AYIYA_Flow;
};

%include ayiya-protocol.pac
%include ayiya-analyzer.pac
