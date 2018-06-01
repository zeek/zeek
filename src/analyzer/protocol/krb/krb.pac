%include binpac.pac
%include bro.pac

%extern{
#include "types.bif.h"
#include "events.bif.h"

namespace analyzer { namespace krb { class KRB_Analyzer; } }
namespace binpac { namespace KRB { class KRB_Conn; } }
typedef analyzer::krb::KRB_Analyzer* KRBAnalyzer;

#include "KRB.h"
%}

extern type KRBAnalyzer;

analyzer KRB withcontext {
	connection:	KRB_Conn;
	flow:		KRB_Flow;
};

connection KRB_Conn(bro_analyzer: KRBAnalyzer) {
	upflow = KRB_Flow(true);
	downflow = KRB_Flow(false);
};

%include krb-protocol.pac

flow KRB_Flow(is_orig: bool) {
	datagram = KRB_PDU(is_orig) withcontext(connection, this);
};

%include krb-analyzer.pac
