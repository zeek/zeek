// See the file "COPYING" in the main distribution directory for copyright.

#include "KRB_TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "types.bif.h"
#include "events.bif.h"

namespace zeek::analyzer::krb_tcp {

KRB_Analyzer::KRB_Analyzer(zeek::Connection* conn)
	: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("KRB_TCP", conn)
	{
	interp = new binpac::KRB_TCP::KRB_Conn(this);
	had_gap = false;
	}

KRB_Analyzer::~KRB_Analyzer()
	{
	delete interp;
	}

void KRB_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void KRB_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void KRB_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
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
		ProtocolViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void KRB_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

} // namespace zeek::analyzer::krb_tcp
