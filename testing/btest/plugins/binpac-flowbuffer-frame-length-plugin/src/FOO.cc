#include "FOO.h"

#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "Reporter.h"

#include "foo.bif.h"

using namespace analyzer::FOO;

FOO_Analyzer::FOO_Analyzer(Connection* c) : tcp::TCP_ApplicationAnalyzer("FOO", c)
	{
	interp = new binpac::FOO::FOO_Conn(this);
	had_gap = false;
	}

FOO_Analyzer::~FOO_Analyzer()
	{
	delete interp;
	}

void FOO_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void FOO_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void FOO_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
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
		printf("Exception: %s\n", e.c_msg());
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void FOO_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
