// See the file "COPYING" in the main distribution directory for copyright.

#include "GSSAPI.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "events.bif.h"

namespace zeek::analyzer::gssapi {

GSSAPI_Analyzer::GSSAPI_Analyzer(zeek::Connection* c)
	: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("GSSAPI", c)
	{
	interp = new binpac::GSSAPI::GSSAPI_Conn(this);
	}

GSSAPI_Analyzer::~GSSAPI_Analyzer()
	{
	delete interp;
	}

void GSSAPI_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void GSSAPI_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void GSSAPI_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	try
		{
		interp->NewData(orig, data, data + len);
		ProtocolConfirmation();
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void GSSAPI_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

} // namespace zeek::analyzer::gssapi
