#include "zeek/analyzer/protocol/rdp/RDP.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/rdp/events.bif.h"
#include "zeek/analyzer/protocol/rdp/types.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::rdp
	{

RDP_Analyzer::RDP_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("RDP", c)
	{
	interp = new binpac::RDP::RDP_Conn(this);

	had_gap = false;
	ssl = nullptr;
	}

RDP_Analyzer::~RDP_Analyzer()
	{
	delete interp;
	}

void RDP_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void RDP_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void RDP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( TCP() && TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	if ( interp->is_encrypted() )
		{
		// 0x00 is RDP native encryption which we don't do anything with now.
		// 0x01 is SSL/TLS
		// 0x03-0x04 is CredSSP which is effectively SSL/TLS
		if ( interp->encryption_method() > 0x00 )
			{
			if ( ! ssl )
				{
				ssl = new analyzer::ssl::SSL_Analyzer(Conn());
				if ( ! AddChildAnalyzer(ssl) )
					{
					reporter->AnalyzerError(this, "failed to add TCP child analyzer "
					                              "to RDP analyzer: already exists");
					return;
					}
				}

			ForwardStream(len, data, orig);
			}
		else
			{
			if ( rdp_native_encrypted_data )
				BifEvent::enqueue_rdp_native_encrypted_data(
					interp->zeek_analyzer(), interp->zeek_analyzer()->Conn(), orig, len);
			}
		}
	else // if not encrypted
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

void RDP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

	} // namespace zeek::analyzer::rdp
