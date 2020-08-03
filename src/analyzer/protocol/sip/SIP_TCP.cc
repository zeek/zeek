// See the file "COPYING" in the main distribution directory for copyright.
//
// TODO: This is preliminary code that's not yet functional and not
// activated. We don't yet support SIP-over-TCP.

#include "SIP_TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "events.bif.h"

using namespace analyzer::sip_tcp;

SIP_Analyzer::SIP_Analyzer(zeek::Connection* conn)
	: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("SIP_TCP", conn)
	{
	interp = new binpac::SIP_TCP::SIP_Conn(this);
	had_gap = false;
	}

SIP_Analyzer::~SIP_Analyzer()
	{
	delete interp;
	}

void SIP_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SIP_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void SIP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can
		// handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SIP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
