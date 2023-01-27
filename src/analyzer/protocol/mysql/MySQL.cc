// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/mysql/MySQL.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/mysql/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::mysql
	{

MySQL_Analyzer::MySQL_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("MySQL", c)
	{
	interp = new binpac::MySQL::MySQL_Conn(this);
	had_gap = false;
	tls_active = false;
	}

MySQL_Analyzer::~MySQL_Analyzer()
	{
	delete interp;
	}

void MySQL_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void MySQL_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);

	if ( tls_active )
		ForwardEndOfData(is_orig);

	interp->FlowEOF(is_orig);
	}

void MySQL_Analyzer::StartTLS()
	{
	tls_active = true;

	Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
	if ( ssl )
		AddChildAnalyzer(ssl);
	}

void MySQL_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( tls_active )
		{
		// If TLS has been initiated, forward to child and
		// short-circuit further processing
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

void MySQL_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

	if ( tls_active )
		ForwardUndelivered(seq, len, orig);

	had_gap = true;
	interp->NewGap(orig, len);
	}

	} // namespace zeek::analyzer::mysql
