#pragma once

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"
#include "rdp_pac.h"

namespace zeek::analyzer::rdp {

class RDP_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {

public:
	explicit RDP_Analyzer(zeek::Connection* conn);
	~RDP_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
		{ return new RDP_Analyzer(conn); }

protected:
	binpac::RDP::RDP_Conn* interp;

	bool had_gap;
	zeek::analyzer::pia::PIA_TCP *pia;
};

} // namespace zeek::analyzer::rdp

namespace analyzer::rdp {

using RDP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::rdp::RDP_Analyzer.")]] = zeek::analyzer::rdp::RDP_Analyzer;

} // namespace analyzer::rdp
