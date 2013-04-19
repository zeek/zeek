
%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer AYIYA withcontext {
	connection:	AYIYA_Conn;
	flow:		AYIYA_Flow;
};

%include ayiya-protocol.pac
%include ayiya-analyzer.pac
