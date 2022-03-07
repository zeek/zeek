// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/krb/KRB_TCP.h"

#include "zeek/analyzer/protocol/krb/events.bif.h"
#include "zeek/analyzer/protocol/krb/types.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::krb_tcp
	{

KRB_Analyzer::KRB_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("KRB_TCP", conn)
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
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void KRB_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void KRB_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( TCP() && TCP()->IsPartial() )
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
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void KRB_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

	} // namespace zeek::analyzer::krb_tcp
