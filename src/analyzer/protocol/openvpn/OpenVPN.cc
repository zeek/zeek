
#include "OpenVPN.h"
#include "analyzer/Manager.h"
#include "analyzer/protocol/ssl/SSL.h"
#include "Reporter.h"
#include "util.h"

#include "openvpn_pac.h"
#include "analyzer/protocol/ssl/ssl_pac.h"

using namespace analyzer::openvpn;

OpenVPN_Analyzer::OpenVPN_Analyzer(Connection* c)
: analyzer::Analyzer("OpenVPN", c)
	{
	interp = new binpac::openvpn::OpenVPN_Conn(this);
	}

OpenVPN_Analyzer::~OpenVPN_Analyzer()
	{
	delete interp;
	}

void OpenVPN_Analyzer::Done()
	{
	Analyzer::Done();
	interp->FlowEOF(true);
	interp->FlowEOF(false);

	if ( ssl )
		{
		ssl->interp->FlowEOF(true);
		ssl->interp->FlowEOF(false);
		}
	}

void OpenVPN_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void OpenVPN_Analyzer::EndOfData(bool is_orig)
	{
	Analyzer::EndOfData(is_orig);
	interp->FlowEOF(is_orig);
	}

void OpenVPN_Analyzer::ForwardSSLData(int len, const u_char* data, bool orig)
	{
	if ( ! ssl )
		{
		ssl = reinterpret_cast<analyzer::ssl::SSL_Analyzer*>(analyzer_mgr->InstantiateAnalyzer("SSL", Conn()));
		if ( ! ssl )
			{
			reporter->InternalError("Could not instantiate SSL Analyzer");
			return;
			}

		AddChildAnalyzer(ssl);
		}

	// Cannot use ForwardStream, due to protocol mismatch.
	// We cheat and use NewData directly.
	try
		{
		ssl->interp->NewData(orig, data, data+len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception when forwarding to SSL analyzer: %s", e.c_msg()));
		}

	// If there was a client hello - let's confirm this as OpenVPN
	if ( ! ProtocolConfirmed() && ssl->ProtocolConfirmed() )
		ProtocolConfirmation();
	}
