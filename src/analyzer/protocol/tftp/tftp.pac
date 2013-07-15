
%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer TFTP withcontext {
	connection: TFTP_Conn;
	flow:       TFTP_Flow;
};

%include tftp-protocol.pac
%include tftp-analyzer.pac
