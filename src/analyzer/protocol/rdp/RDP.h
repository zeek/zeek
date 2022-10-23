#pragma once

#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/rdp/events.bif.h"
#include "zeek/analyzer/protocol/rdp/rdp_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::rdp
	{

class RDP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{

public:
	explicit RDP_Analyzer(Connection* conn);
	~RDP_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new RDP_Analyzer(conn);
		}

protected:
	binpac::RDP::RDP_Conn* interp;

	bool had_gap;
	analyzer::pia::PIA_TCP* pia;
	};

	} // namespace zeek::analyzer::rdp
