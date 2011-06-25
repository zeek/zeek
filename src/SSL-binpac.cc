#include "SSL-binpac.h"
#include "TCP_Reassembler.h"
#include "Logger.h"
#include "util.h"


bool SSL_Analyzer_binpac::warnings_generated = false;

SSL_Analyzer_binpac::SSL_Analyzer_binpac(Connection* c)
: TCP_ApplicationAnalyzer(AnalyzerTag::SSL, c)
	{
	interp = new binpac::SSL::SSLAnalyzer;
	interp->set_bro_analyzer(this);

	if ( ! warnings_generated )
		generate_warnings();
	}

SSL_Analyzer_binpac::~SSL_Analyzer_binpac()
	{
	delete interp;
	}

void SSL_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SSL_Analyzer_binpac::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}

void SSL_Analyzer_binpac::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		return;

	interp->NewData(orig, data, data + len);
	}

void SSL_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

void SSL_Analyzer_binpac::warn_(const char* msg)
	{
	bro_logger->Warning("SSL_Analyzer_binpac: ", msg);
	}

void SSL_Analyzer_binpac::generate_warnings()
	{
	if ( ssl_store_certificates )
		warn_("storage of certificates (ssl_store_certificates) not supported");
	if ( ssl_store_key_material )
		warn_("storage of key material (ssl_store_key_material) not supported");

	warnings_generated = true;
	}
