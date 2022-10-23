#include "zeek/analyzer/protocol/socks/SOCKS.h"

#include "zeek/analyzer/protocol/socks/events.bif.h"
#include "zeek/analyzer/protocol/socks/socks_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::socks
	{

SOCKS_Analyzer::SOCKS_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("SOCKS", conn)
	{
	interp = new binpac::SOCKS::SOCKS_Conn(this);
	orig_done = resp_done = false;
	pia = nullptr;
	}

SOCKS_Analyzer::~SOCKS_Analyzer()
	{
	delete interp;
	}

void SOCKS_Analyzer::EndpointDone(bool orig)
	{
	if ( orig )
		orig_done = true;
	else
		resp_done = true;
	}

void SOCKS_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SOCKS_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void SOCKS_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( TCP() && TCP()->IsPartial() )
		return;

	if ( orig_done && resp_done )
		{
		// Finished decapsulating tunnel layer. Now do standard processing
		// with the rest of the connection.
		//
		// Note that we assume that no payload data arrives before both endpoints
		// are done with their part of the SOCKS protocol.
		if ( ! pia )
			{
			pia = new analyzer::pia::PIA_TCP(Conn());
			if ( AddChildAnalyzer(pia) )
				{
				pia->FirstPacket(true, nullptr);
				pia->FirstPacket(false, nullptr);
				}
			else
				pia = nullptr;
			}

		ForwardStream(len, data, orig);
		}
	else
		{
		try
			{
			interp->NewData(orig, data, data + len);
			}
		catch ( const binpac::Exception& e )
			{
			AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
			}
		}
	}

void SOCKS_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

	} // namespace zeek::analyzer::socks
