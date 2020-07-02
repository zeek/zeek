#pragma once

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "rfb_pac.h"

namespace analyzer { namespace rfb {

class RFB_Analyzer final : public tcp::TCP_ApplicationAnalyzer {

public:
	explicit RFB_Analyzer(Connection* conn);
	~RFB_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RFB_Analyzer(conn); }

protected:
	binpac::RFB::RFB_Conn* interp;

	bool had_gap;
	bool invalid;

};

} } // namespace analyzer::*
