#pragma once

#include "zeek/analyzer/protocol/rfb/events.bif.h"
#include "zeek/analyzer/protocol/rfb/rfb_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::rfb
	{

class RFB_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{

public:
	explicit RFB_Analyzer(Connection* conn);
	~RFB_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new RFB_Analyzer(conn);
		}

protected:
	binpac::RFB::RFB_Conn* interp;

	bool had_gap;
	bool invalid;
	};

	} // namespace zeek::analyzer::rfb
