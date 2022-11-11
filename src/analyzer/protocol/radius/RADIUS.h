#pragma once

#include "zeek/analyzer/protocol/radius/events.bif.h"
#include "zeek/analyzer/protocol/radius/radius_pac.h"

namespace zeek::analyzer::radius
	{

class RADIUS_Analyzer final : public analyzer::Analyzer
	{
public:
	explicit RADIUS_Analyzer(Connection* conn);
	~RADIUS_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
	                   int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new RADIUS_Analyzer(conn); }

protected:
	binpac::RADIUS::RADIUS_Conn* interp;
	};

	} // namespace zeek::analyzer::radius
