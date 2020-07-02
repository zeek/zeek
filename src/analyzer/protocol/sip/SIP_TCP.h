// See the file "COPYING" in the main distribution directory for copyright.
//
// TODO: This is preliminary code that's not yet functional and not
// activated. We don't yet support SIP-over-TCP.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

#include "sip_TCP_pac.h"

namespace analyzer { namespace sip_tcp {

class SIP_Analyzer final : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit SIP_Analyzer(Connection* conn);
	~SIP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SIP_Analyzer(conn); }

protected:
	binpac::SIP_TCP::SIP_Conn* interp;
	bool had_gap;
};

} } // namespace analyzer::*
