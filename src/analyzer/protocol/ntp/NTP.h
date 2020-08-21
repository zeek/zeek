#pragma once

#include "events.bif.h"
#include "types.bif.h"

#include "analyzer/protocol/udp/UDP.h"

#include "ntp_pac.h"

namespace zeek::analyzer::ntp {

class NTP_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit NTP_Analyzer(zeek::Connection* conn);
	~NTP_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new NTP_Analyzer(conn); }

protected:
	binpac::NTP::NTP_Conn* interp;
};

} // namespace zeek::analyzer::ntp

namespace analyzer::NTP {

using NTP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::ntp::NTP_Analyzer.")]] = zeek::analyzer::ntp::NTP_Analyzer;

} // namespace analyzer::NTP
