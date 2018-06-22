%include binpac.pac
%include bro.pac

%extern{
#include "types.bif.h"
#include "events.bif.h"

namespace analyzer { namespace krb_tcp { class KRB_Analyzer; } }
namespace binpac { namespace KRB_TCP { class KRB_Conn; } }
typedef analyzer::krb_tcp::KRB_Analyzer* KRBTCPAnalyzer;

#include "KRB_TCP.h"
%}

extern type KRBTCPAnalyzer;

analyzer KRB_TCP withcontext {
	connection:	KRB_Conn;
	flow:		KRB_Flow;
};

connection KRB_Conn(bro_analyzer: KRBTCPAnalyzer) {
	upflow = KRB_Flow(true);
	downflow = KRB_Flow(false);
};

%include krb-protocol.pac

flow KRB_Flow(is_orig: bool) {
	flowunit = KRB_PDU_TCP(is_orig) withcontext(connection, this);
};

%include krb-analyzer.pac
