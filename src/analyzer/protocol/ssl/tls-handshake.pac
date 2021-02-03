# Binpac analyzer just for the TLS handshake protocol and nothing else

%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/Desc.h"

#include "zeek/analyzer/protocol/ssl/types.bif.h"
#include "zeek/analyzer/protocol/ssl/events.bif.h"
%}

analyzer TLSHandshake withcontext {
	connection: Handshake_Conn;
	flow:       Handshake_Flow;
};

connection Handshake_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = Handshake_Flow(true);
	downflow = Handshake_Flow(false);
};

%include ssl-defs.pac
%include tls-handshake-protocol.pac

flow Handshake_Flow(is_orig: bool) {
	flowunit = HandshakePDU(is_orig) withcontext(connection, this);
}

%include tls-handshake-analyzer.pac
