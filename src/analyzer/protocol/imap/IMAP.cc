// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/imap/IMAP.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::imap
	{

IMAP_Analyzer::IMAP_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("IMAP", conn)
	{
	interp = new binpac::IMAP::IMAP_Conn(this);
	had_gap = false;
	tls_active = false;
	}

IMAP_Analyzer::~IMAP_Analyzer()
	{
	delete interp;
	}

void IMAP_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void IMAP_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void IMAP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( tls_active )
		{
		// If TLS has been initiated, forward to child and abort further
		// processing
		ForwardStream(len, data, orig);
		return;
		}

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

void IMAP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void IMAP_Analyzer::StartTLS()
	{
	// StartTLS was called. This means we saw a client starttls followed
	// by a server proceed. From here on, everything should be a binary
	// TLS datastream.
	tls_active = true;

	Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
	if ( ssl )
		AddChildAnalyzer(ssl);
	}

	} // namespace zeek::analyzer::imap
