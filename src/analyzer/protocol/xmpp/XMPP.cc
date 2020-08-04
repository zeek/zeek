// See the file "COPYING" in the main distribution directory for copyright.

#include "XMPP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "analyzer/Manager.h"

namespace zeek::analyzer::xmpp {

XMPP_Analyzer::XMPP_Analyzer(zeek::Connection* conn)
	: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("XMPP", conn)
	{
	interp = unique_ptr<binpac::XMPP::XMPP_Conn>(new binpac::XMPP::XMPP_Conn(this));
	had_gap = false;
	tls_active = false;
	}

XMPP_Analyzer::~XMPP_Analyzer()
	{
	}

void XMPP_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void XMPP_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void XMPP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
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
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void XMPP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void XMPP_Analyzer::StartTLS()
	{
	// StartTLS was called. This means we saw a client starttls followed
	// by a server proceed. From here on, everything should be a binary
	// TLS datastream.

	tls_active = true;

	Analyzer* ssl = zeek::analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
	if ( ssl )
		AddChildAnalyzer(ssl);
	}

} // namespace zeek::analyzer::xmpp
