%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/protocol/socks/SOCKS.h"
#include "zeek/Reporter.h"

#include "zeek/analyzer/protocol/socks/events.bif.h"
%}

analyzer SOCKS withcontext {
    connection: SOCKS_Conn;
    flow:       SOCKS_Flow;
};

connection SOCKS_Conn(zeek_analyzer: ZeekAnalyzer) {
    upflow   = SOCKS_Flow(true);
    downflow = SOCKS_Flow(false);
};

%include socks-protocol.pac

flow SOCKS_Flow(is_orig: bool) {
	datagram = SOCKS_Message(is_orig) withcontext(connection, this);
};

%include socks-analyzer.pac
