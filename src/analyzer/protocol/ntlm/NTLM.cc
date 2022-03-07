// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/ntlm/NTLM.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/ntlm/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::ntlm
	{

NTLM_Analyzer::NTLM_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("NTLM", c)
	{
	interp = new binpac::NTLM::NTLM_Conn(this);
	}

NTLM_Analyzer::~NTLM_Analyzer()
	{
	delete interp;
	}

void NTLM_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void NTLM_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void NTLM_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	try
		{
		interp->NewData(orig, data, data + len);
		AnalyzerConfirmation();
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void NTLM_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

	} // namespace zeek::analyzer::ntlm
