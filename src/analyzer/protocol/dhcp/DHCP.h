#pragma once

#include "zeek/analyzer/protocol/udp/UDP.h"

#include "analyzer/protocol/dhcp/dhcp_pac.h"

namespace zeek::analyzer::dhcp {

class DHCP_Analyzer final : public analyzer::Analyzer {
public:
	explicit DHCP_Analyzer(Connection* conn);
	~DHCP_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DHCP_Analyzer(conn); }

protected:
	binpac::DHCP::DHCP_Conn* interp;
};

} // namespace zeek::analyzer::dhcp
