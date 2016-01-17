#ifndef ANALYZER_PROTOCOL_SSL_SSL_H
#define ANALYZER_PROTOCOL_SSL_SSL_H

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"

namespace binpac { namespace SSL { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace analyzer { namespace ssl {

class SSL_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	SSL_Analyzer(Connection* conn);
	virtual ~SSL_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	void SendHandshake(const u_char* begin, const u_char* end, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SSL_Analyzer(conn); }

protected:
	binpac::SSL::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	bool had_gap;

};

} } // namespace analyzer::* 

#endif
