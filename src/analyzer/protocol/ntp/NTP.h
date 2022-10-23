#pragma once

#include "zeek/analyzer/protocol/ntp/events.bif.h"
#include "zeek/analyzer/protocol/ntp/ntp_pac.h"
#include "zeek/analyzer/protocol/ntp/types.bif.h"

namespace zeek::analyzer::ntp
	{

class NTP_Analyzer final : public analyzer::Analyzer
	{
public:
	explicit NTP_Analyzer(Connection* conn);
	~NTP_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
	                   int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new NTP_Analyzer(conn); }

protected:
	binpac::NTP::NTP_Conn* interp;
	};

	} // namespace zeek::analyzer::ntp
