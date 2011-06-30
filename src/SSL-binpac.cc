#include "SSL-binpac.h"
#include "TCP_Reassembler.h"
#include "util.h"

SSL_Analyzer_binpac::SSL_Analyzer_binpac(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::SSL, c)
	{
	interp = new binpac::SSL::SSL_Conn(this);
	}

SSL_Analyzer_binpac::~SSL_Analyzer_binpac()
	{
	delete interp;
	}

void SSL_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SSL_Analyzer_binpac::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}

void SSL_Analyzer_binpac::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		return;

	interp->NewData(orig, data, data + len);
	}

void SSL_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
