// $Id:$

#ifndef ssl_binpac_h
#define ssl_binpac_h

#include "TCP.h"

#include "ssl_pac.h"
#include "ssl-record-layer_pac.h"

class SSL_Analyzer_binpac : public TCP_ApplicationAnalyzer {
public:
	SSL_Analyzer_binpac(Connection* conn);
	virtual ~SSL_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SSL_Analyzer_binpac(conn); }

	static bool Available()
		{
		return FLAGS_use_binpac &&
			(ssl_certificate_seen || ssl_certificate ||
			 ssl_conn_attempt || ssl_conn_server_reply ||
			 ssl_conn_established || ssl_conn_reused ||
			 ssl_conn_alert);
		}

	static bool warnings_generated;
	static void warn_(const char* msg);
	static void generate_warnings();

protected:
	binpac::SSLRecordLayer::SSLRecordLayerAnalyzer* records;
	binpac::SSL::SSLAnalyzer* ssl;
};

#endif
