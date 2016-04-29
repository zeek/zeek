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

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	void StartTLS();

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new XMPP_Analyzer(conn); }

protected:
	std::unique_ptr<binpac::XMPP::XMPP_Conn> interp;
	bool had_gap;

	bool tls_active;
};

} } // namespace analyzer::*

#endif /* ANALYZER_PROTOCOL_XMPP_XMPP_H */
