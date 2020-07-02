#pragma once

#include "analyzer/protocol/udp/UDP.h"

#include "dhcp_pac.h"

namespace analyzer { namespace dhcp {

class DHCP_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit DHCP_Analyzer(Connection* conn);
	~DHCP_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DHCP_Analyzer(conn); }

protected:
	binpac::DHCP::DHCP_Conn* interp;
};

} } // namespace analyzer::*
