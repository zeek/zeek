# $Id: dce_rpc.pac 4608 2007-07-05 18:23:58Z vern $

%include binpac.pac
%include bro.pac

analyzer DCE_RPC withcontext {
	connection: DCE_RPC_Conn;
	flow: DCE_RPC_Flow;
};

%include "dce_rpc-protocol.pac"
%include "dce_rpc-analyzer.pac"
