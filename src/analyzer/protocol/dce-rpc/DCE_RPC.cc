// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/dce-rpc/DCE_RPC.h"

#include "zeek/zeek-config.h"

#include <cstdlib>
#include <map>
#include <string>

using namespace std;

namespace zeek::analyzer::dce_rpc
	{

DCE_RPC_Analyzer::DCE_RPC_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("DCE_RPC", conn)
	{
	had_gap = false;
	interp = new binpac::DCE_RPC::DCE_RPC_Conn(this);
	}

DCE_RPC_Analyzer::~DCE_RPC_Analyzer()
	{
	delete interp;
	}

void DCE_RPC_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void DCE_RPC_Analyzer::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void DCE_RPC_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void DCE_RPC_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
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

	} // namespace zeek::analyzer::dce_rpc
