#include "RFB.h"

#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::rfb;

RFB_Analyzer::RFB_Analyzer(zeek::Connection* c)

: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("RFB", c)

	{
	interp = new binpac::RFB::RFB_Conn(this);
	had_gap = false;
	invalid = false;
	}

RFB_Analyzer::~RFB_Analyzer()
	{
	delete interp;
	}

void RFB_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);

	}

void RFB_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void RFB_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	if ( invalid )
		return;

	if ( interp->saw_handshake() && ! orig )
		// Don't try parsing server data after the handshake
		// (it's not completely implemented and contains mostly
		// uninteresting pixel data).
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		invalid = true;
		}
	}

void RFB_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
