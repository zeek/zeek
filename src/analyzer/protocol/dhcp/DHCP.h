#pragma once

#include "analyzer/protocol/udp/UDP.h"

#include "dhcp_pac.h"

namespace zeek::analyzer::dhcp {

class DHCP_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit DHCP_Analyzer(zeek::Connection* conn);
	~DHCP_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new DHCP_Analyzer(conn); }

protected:
	binpac::DHCP::DHCP_Conn* interp;
};

} // namespace zeek::analyzer::dhcp

namespace analyzer::dhcp {
	using DHCP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::dhcp::DHCP_Analyzer.")]] = zeek::analyzer::dhcp::DHCP_Analyzer;
}
