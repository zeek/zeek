#pragma once

#include "zeek/analyzer/protocol/udp/UDP.h"

#include "analyzer/protocol/rdp/events.bif.h"
#include "analyzer/protocol/rdp/rdpeudp_pac.h"

namespace zeek::analyzer::rdpeudp {

class RDP_Analyzer final : public analyzer::Analyzer {

public:
	explicit RDP_Analyzer(Connection* conn);
	~RDP_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RDP_Analyzer(conn); }

protected:
	binpac::RDPEUDP::RDPEUDP_Conn* interp;
};

} // namespace zeek::analyzer::rdpeudp
