#pragma once

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"
#include "rdp_pac.h"

namespace analyzer { namespace rdp {

class RDP_Analyzer final : public tcp::TCP_ApplicationAnalyzer {

public:
	explicit RDP_Analyzer(Connection* conn);
	~RDP_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RDP_Analyzer(conn); }

protected:
	binpac::RDP::RDP_Conn* interp;

	bool had_gap;
	pia::PIA_TCP *pia;
};

} } // namespace analyzer::*
