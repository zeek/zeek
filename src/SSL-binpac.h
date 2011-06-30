#ifndef ssl_binpac_h
#define ssl_binpac_h

#include "TCP.h"

#include "ssl_pac.h"

class SSL_Analyzer_binpac : public TCP_ApplicationAnalyzer {
public:
	SSL_Analyzer_binpac(Connection* conn);
	virtual ~SSL_Analyzer_binpac();

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);

	// Overriden from TCP_ApplicationAnalyzer
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SSL_Analyzer_binpac(conn); }

	static bool Available()
		{
		return ( ssl_client_hello || ssl_server_hello ||
			ssl_established || ssl_extension || ssl_alert ||
			x509_certificate || x509_extension || x509_error );
		}

protected:
	binpac::SSL::SSL_Conn* interp;
	
};

#endif
