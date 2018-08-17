// See the file "COPYING" in the main distribution directory for copyright.
//
// TODO: This is preliminary code that's not yet functional and not
// activated. We don't yet support SIP-over-TCP.

#ifndef ANALYZER_PROTOCOL_SIP_SIP_TCP_H
#define ANALYZER_PROTOCOL_SIP_SIP_TCP_H

#include "analyzer/protocol/tcp/TCP.h"

#include "sip_TCP_pac.h"

namespace analyzer { namespace sip_tcp {

class SIP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit SIP_Analyzer(Connection* conn);
	~SIP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SIP_Analyzer(conn); }

protected:
	binpac::SIP_TCP::SIP_Conn* interp;
	bool had_gap;
};

} } // namespace analyzer::*

#endif
