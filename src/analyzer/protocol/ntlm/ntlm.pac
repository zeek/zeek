%include binpac.pac
%include bro.pac

%extern{
#include "analyzer/Manager.h"
#include "analyzer/Analyzer.h"

#include "types.bif.h"
#include "events.bif.h"
%}

analyzer NTLM withcontext {
	connection : NTLM_Conn;
	flow       : NTLM_Flow;
};

connection NTLM_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = NTLM_Flow(true);
	downflow = NTLM_Flow(false);
};

%include ntlm-protocol.pac
%include ../asn1/asn1.pac

# Now we define the flow:
flow NTLM_Flow(is_orig: bool) {
	datagram = NTLM_SSP_Token(is_orig) withcontext(connection, this);
};

%include ntlm-analyzer.pac