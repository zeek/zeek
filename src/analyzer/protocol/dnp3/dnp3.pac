
%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer DNP3 withcontext {
	connection:	DNP3_Conn;
	flow:		DNP3_Flow;
};

%include dnp3-protocol.pac
%include dnp3-analyzer.pac

