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
	
	%member{
		bool permessage_compression_enabled_;	
	%}

	%init{
		permessage_compression_enabled_ = false;
	%}

	function EnablePerMessageCompression(): void
		%{
		permessage_compression_enabled = true;
		%}
	function HasPerMessageCompressionEnabled(): bool
		%{
		return permessage_compression_enabled_;
		%}
};

%include websocket-protocol.pac
%include websocket-analyzer.pac
