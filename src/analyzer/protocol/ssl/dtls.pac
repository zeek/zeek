# binpac file for SSL analyzer

%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer DTLS withcontext {
	connection: SSL_Conn;
	flow:       DTLS_Flow;
};

connection SSL_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DTLS_Flow(true);
	downflow = DTLS_Flow(false);
};

%include ssl-dtls-protocol.pac
%include dtls-protocol.pac

flow DTLS_Flow(is_orig: bool) {
#	flowunit = SSLRecord(is_orig) withcontext(connection, this);
  datagram = DTLSPDU(is_orig) withcontext(connection, this);
}

%include ssl-dtls-analyzer.pac
%include dtls-analyzer.pac
%include ssl-defs.pac
