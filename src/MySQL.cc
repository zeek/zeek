#include "MySQL.h"
#include "TCP_Reassembler.h"
#include "Reporter.h"
#include "util.h"

MySQL_Analyzer::MySQL_Analyzer(Connection *c)
: TCP_ApplicationAnalyzer(AnalyzerTag::MySQL, c)
	{
	interp = new binpac::MySQL::MySQL_Conn(this);
	had_gap = false;
	}

MySQL_Analyzer::~MySQL_Analyzer()
	{
	delete interp;
	}

void MySQL_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void MySQL_Analyzer::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void MySQL_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
			printf("Binpac exception: %s\n", e.c_msg());
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void MySQL_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
