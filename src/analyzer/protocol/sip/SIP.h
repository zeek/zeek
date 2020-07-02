#pragma once

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"
#include "sip_pac.h"

namespace analyzer { namespace SIP {

class SIP_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit SIP_Analyzer(Connection* conn);
	~SIP_Analyzer() override;

	// Overridden from Analyzer

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
				   	   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
	{ return new SIP_Analyzer(conn); }

protected:
	binpac::SIP::SIP_Conn* interp;
};

} } // namespace analyzer::*
