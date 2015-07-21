// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_XMPP_XMPP_H
#define ANALYZER_PROTOCOL_XMPP_XMPP_H

#include "analyzer/protocol/tcp/TCP.h"

#include "xmpp_pac.h"

namespace analyzer { namespace xmpp {

class XMPP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	XMPP_Analyzer(Connection* conn);
	virtual ~XMPP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	void StartTLS();

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new XMPP_Analyzer(conn); }

protected:
	binpac::XMPP::XMPP_Conn* interp;
	bool had_gap;

	bool tls_active;
};

} } // namespace analyzer::*

#endif /* ANALYZER_PROTOCOL_XMPP_XMPP_H */
