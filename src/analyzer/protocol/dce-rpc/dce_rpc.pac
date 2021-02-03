%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/protocol/dce-rpc/consts.bif.h"
#include "zeek/analyzer/protocol/dce-rpc/types.bif.h"
#include "zeek/analyzer/protocol/dce-rpc/events.bif.h"
%}

analyzer DCE_RPC withcontext {
	connection : DCE_RPC_Conn;
	flow       : DCE_RPC_Flow;
};

connection DCE_RPC_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = DCE_RPC_Flow(true);
	downflow = DCE_RPC_Flow(false);
};

%include dce_rpc-protocol.pac

%include endpoint-atsvc.pac
%include endpoint-epmapper.pac
%include dce_rpc-analyzer.pac
%include dce_rpc-auth.pac
