%include binpac.pac
%include bro.pac

%extern{
#include "analyzer/Manager.h"
#include "analyzer/Analyzer.h"

#include "events.bif.h"
%}

analyzer GSSAPI withcontext {
	connection : GSSAPI_Conn;
	flow       : GSSAPI_Flow;
};

connection GSSAPI_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = GSSAPI_Flow(true);
	downflow = GSSAPI_Flow(false);
};

%include gssapi-protocol.pac
%include ../asn1/asn1.pac

# Now we define the flow:
flow GSSAPI_Flow(is_orig: bool) {
	datagram = GSSAPI_NEG_TOKEN(is_orig) withcontext(connection, this);
};

%include gssapi-analyzer.pac
