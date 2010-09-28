// $Id:$

#include "SSL-binpac.h"
#include "TCP_Reassembler.h"
#include "util.h"


bool SSL_Analyzer_binpac::warnings_generated = false;

SSL_Analyzer_binpac::SSL_Analyzer_binpac(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::SSL_BINPAC, c)
	{
	ssl = new binpac::SSL::SSLAnalyzer;
	ssl->set_bro_analyzer(this);

	records = new binpac::SSLRecordLayer::SSLRecordLayerAnalyzer;
	records->set_ssl_analyzer(ssl);

	if ( ! warnings_generated )
		generate_warnings();
	}

SSL_Analyzer_binpac::~SSL_Analyzer_binpac()
	{
	delete records;
	delete ssl;
	}

void SSL_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	records->FlowEOF(true);
	records->FlowEOF(false);
	}

void SSL_Analyzer_binpac::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	records->FlowEOF(endp->IsOrig());
	ssl->FlowEOF(endp->IsOrig());
	}

void SSL_Analyzer_binpac::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		return;

	records->NewData(orig, data, data + len);
	}

void SSL_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	records->NewGap(orig, len);
	}

void SSL_Analyzer_binpac::warn_(const char* msg)
	{
	warn("SSL_Analyzer_binpac: ", msg);
	}

void SSL_Analyzer_binpac::generate_warnings()
	{
	if ( ssl_store_certificates )
		warn_("storage of certificates (ssl_store_certificates) not supported");
	if ( ssl_store_key_material )
		warn_("storage of key material (ssl_store_key_material) not supported");

#ifndef USE_OPENSSL
	if ( ssl_verify_certificates )
		warn_("verification of certificates (ssl_verify_certificates) not supported due to non-existing OpenSSL support");
#endif

	warnings_generated = true;
	}
