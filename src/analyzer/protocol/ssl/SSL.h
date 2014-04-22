#ifndef ANALYZER_PROTOCOL_SSL_SSL_H
#define ANALYZER_PROTOCOL_SSL_SSL_H

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"
#include "ssl_pac.h"

namespace analyzer { namespace ssl {

class SSL_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	SSL_Analyzer(Connection* conn);
	virtual ~SSL_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SSL_Analyzer(conn); }

	static bool Available()
		{
		return ( ssl_client_hello || ssl_server_hello ||
			ssl_established || ssl_extension || ssl_alert );
		}

protected:
	binpac::SSL::SSL_Conn* interp;
	bool had_gap;

};

} } // namespace analyzer::* 

#endif
