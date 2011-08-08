// $Id:$
//
// This template code contributed by Kristin Stephens.

#include "DNP3-TCP.h"
#include "TCP_Reassembler.h"

DNP3TCP_Analyzer::DNP3TCP_Analyzer(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::Dnp3TCP, c)
	{
	interp = new binpac::Dnp3TCP::Dnp3TCP_Conn(this);
	}

DNP3TCP_Analyzer::~DNP3TCP_Analyzer()
	{
	delete interp;
	}

void DNP3TCP_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void DNP3TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	interp->NewData(orig, data, data + len);
	}

void DNP3TCP_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	}

void DNP3TCP_Analyzer::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}
