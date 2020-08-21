#pragma once

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"

#include "rfb_pac.h"

namespace zeek::analyzer::rfb {

class RFB_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {

public:
	explicit RFB_Analyzer(zeek::Connection* conn);
	~RFB_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overriden from zeek::analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
		{ return new RFB_Analyzer(conn); }

protected:
	binpac::RFB::RFB_Conn* interp;

	bool had_gap;
	bool invalid;

};

} // namespace zeek::analyzer::rfb

namespace analyzer::rfb {

using RFB_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::rfb::RFB_Analyzer.")]] = zeek::analyzer::rfb::RFB_Analyzer;

} // namespace analyzer::rfb
