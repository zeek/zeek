%include binpac.pac
%include bro.pac

%extern{
#include "types.bif.h"
#include "events.bif.h"
%}

analyzer KRB withcontext {
	connection:	KRB_Conn;
	flow:		KRB_Flow;
};

%include krb-protocol.pac
%include krb-analyzer.pac
