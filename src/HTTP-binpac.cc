#include "HTTP-binpac.h"
#include "TCP_Reassembler.h"

HTTP_Analyzer_binpac::HTTP_Analyzer_binpac(Connection *c)
: TCP_ApplicationAnalyzer(AnalyzerTag::HTTP_BINPAC, c)
	{
	interp = new binpac::HTTP::HTTP_Conn(this);
	}

HTTP_Analyzer_binpac::~HTTP_Analyzer_binpac()
	{
	delete interp;
	}

void HTTP_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void HTTP_Analyzer_binpac::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void HTTP_Analyzer_binpac::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	interp->NewData(orig, data, data + len);
	}

void HTTP_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
