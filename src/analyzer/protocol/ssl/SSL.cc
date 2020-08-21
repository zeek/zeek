
#include "SSL.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "util.h"

#include "events.bif.h"
#include "ssl_pac.h"
#include "tls-handshake_pac.h"

namespace zeek::analyzer::ssl {

SSL_Analyzer::SSL_Analyzer(zeek::Connection* c)
: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("SSL", c)
	{
	interp = new binpac::SSL::SSL_Conn(this);
	handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
	had_gap = false;
	}

SSL_Analyzer::~SSL_Analyzer()
	{
	delete interp;
	delete handshake_interp;
	}

void SSL_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	handshake_interp->FlowEOF(true);
	handshake_interp->FlowEOF(false);
	}

void SSL_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	handshake_interp->FlowEOF(is_orig);
	}

void SSL_Analyzer::StartEncryption()
	{
	interp->startEncryption(true);
	interp->startEncryption(false);
	interp->setEstablished();
	}

void SSL_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

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
		ProtocolViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig)
	{
	handshake_interp->set_record_version(raw_tls_version);
	try
		{
		handshake_interp->NewData(orig, begin, end);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

} // namespace zeek::analyzer::ssl
