%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/Analyzer.h"

#include "zeek/analyzer/protocol/gssapi/events.bif.h"
%}

analyzer GSSAPI withcontext {
	connection : GSSAPI_Conn;
	flow       : GSSAPI_Flow;
};

connection GSSAPI_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow   = GSSAPI_Flow(true);
	downflow = GSSAPI_Flow(false);
};

%include gssapi-protocol.pac
%include ../asn1/asn1.pac

# Now we define the flow:
flow GSSAPI_Flow(is_orig: bool) {
	datagram = GSSAPI_SELECT(is_orig) withcontext(connection, this);
};

%include gssapi-analyzer.pac
