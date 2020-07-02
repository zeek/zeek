#pragma once

#include "events.bif.h"
#include "types.bif.h"

#include "analyzer/protocol/udp/UDP.h"

#include "ntp_pac.h"

namespace analyzer { namespace NTP {

class NTP_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit NTP_Analyzer(Connection* conn);
	~NTP_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new NTP_Analyzer(conn); }

protected:
	binpac::NTP::NTP_Conn* interp;
};

} } // namespace analyzer::*
