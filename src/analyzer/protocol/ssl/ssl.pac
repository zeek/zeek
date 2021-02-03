# binpac file for SSL analyzer

# split in three parts:
#  - ssl-protocol.pac: describes the SSL protocol messages
#  - ssl-analyzer.pac: contains the SSL analyzer code
#  - ssl-record-layer.pac: describes the SSL record layer

%include binpac.pac
%include zeek.pac

%extern{

namespace zeek::analyzer::ssl { class SSL_Analyzer; }
using SSLAnalyzer = zeek::analyzer::ssl::SSL_Analyzer*;

#include "zeek/Desc.h"
#include "zeek/analyzer/protocol/ssl/SSL.h"

#include "zeek/analyzer/protocol/ssl/events.bif.h"
%}

extern type SSLAnalyzer;

analyzer SSL withcontext {
	connection: SSL_Conn;
	flow:       SSL_Flow;
};

connection SSL_Conn(zeek_analyzer: SSLAnalyzer) {
	upflow = SSL_Flow(true);
	downflow = SSL_Flow(false);
};

%include ssl-dtls-protocol.pac
%include ssl-protocol.pac

flow SSL_Flow(is_orig: bool) {
	flowunit = SSLPDU(is_orig) withcontext(connection, this);
}

%include ssl-dtls-analyzer.pac
%include ssl-analyzer.pac
%include ssl-defs.pac
