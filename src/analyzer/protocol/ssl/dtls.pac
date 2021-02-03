# binpac file for SSL analyzer

%include binpac.pac
%include zeek.pac

%extern{

namespace zeek::analyzer::dtls { class DTLS_Analyzer; }
using DTLSAnalyzer = zeek::analyzer::dtls::DTLS_Analyzer*;

#include "zeek/analyzer/protocol/ssl/DTLS.h"

#include "zeek/analyzer/protocol/ssl/events.bif.h"
#include "zeek/analyzer/protocol/ssl/consts.bif.h"
%}

extern type DTLSAnalyzer;

analyzer DTLS withcontext {
	connection: SSL_Conn;
	flow:       DTLS_Flow;
};

connection SSL_Conn(zeek_analyzer: DTLSAnalyzer) {
	upflow = DTLS_Flow(true);
	downflow = DTLS_Flow(false);
};

%include ssl-dtls-protocol.pac
%include dtls-protocol.pac

flow DTLS_Flow(is_orig: bool) {
  datagram = DTLSPDU(is_orig) withcontext(connection, this);
}

%include ssl-dtls-analyzer.pac
%include dtls-analyzer.pac
%include ssl-defs.pac
