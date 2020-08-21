// See the file "COPYING" in the main distribution directory for copyright.

#include "IMAP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "analyzer/Manager.h"

namespace zeek::analyzer::imap {

IMAP_Analyzer::IMAP_Analyzer(zeek::Connection* conn)
	: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("IMAP", conn)
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
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void IMAP_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void IMAP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( tls_active )
		{
		// If TLS has been initiated, forward to child and abort further
		// processing
		ForwardStream(len, data, orig);
		return;
		}

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

void IMAP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void IMAP_Analyzer::StartTLS()
	{
	// StartTLS was called. This means we saw a client starttls followed
	// by a server proceed. From here on, everything should be a binary
	// TLS datastream.
	tls_active = true;

	Analyzer* ssl = zeek::analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
	if ( ssl )
		AddChildAnalyzer(ssl);
	}

} // namespace zeek::analyzer::imap
