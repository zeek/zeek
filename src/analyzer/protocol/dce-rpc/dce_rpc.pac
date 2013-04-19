%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer DCE_RPC withcontext {
	connection: DCE_RPC_Conn;
	flow: DCE_RPC_Flow;
};

%include dce_rpc-protocol.pac
%include dce_rpc-analyzer.pac
