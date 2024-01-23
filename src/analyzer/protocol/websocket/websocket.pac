# See the file "COPYING" in the main distribution directory for copyright.

%include binpac.pac
%include zeek.pac

%extern{
#include <array>

#include "zeek/analyzer/protocol/websocket/consts.bif.h"
#include "zeek/analyzer/protocol/websocket/events.bif.h"
%}

analyzer WebSocket withcontext {
	connection: WebSocket_Conn;
	flow: WebSocket_Flow;
};

connection WebSocket_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = WebSocket_Flow(true);
	downflow = WebSocket_Flow(false);
};

%include websocket-protocol.pac
%include websocket-analyzer.pac
