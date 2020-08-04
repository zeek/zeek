#pragma once

#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "rdpeudp_pac.h"

namespace zeek::analyzer::rdpeudp {

class RDP_Analyzer final : public zeek::analyzer::Analyzer {

public:
	explicit RDP_Analyzer(zeek::Connection* conn);
	~RDP_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;
	static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
		{ return new RDP_Analyzer(conn); }

protected:
	binpac::RDPEUDP::RDPEUDP_Conn* interp;
};

} // namespace zeek::analyzer::rdpeudp

namespace analyzer::rdpeudp {

using RDP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::rdpeudp::RDP_Analyzer.")]] = zeek::analyzer::rdpeudp::RDP_Analyzer;

} // namespace analyzer::rdpeudp
