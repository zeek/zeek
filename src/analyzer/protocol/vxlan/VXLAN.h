// See the file  in the main distribution directory for copyright.

#pragma once

#include "analyzer/Analyzer.h"

namespace analyzer { namespace vxlan {

class VXLAN_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit VXLAN_Analyzer(Connection* conn)
	    : Analyzer("VXLAN", conn)
		{}

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new VXLAN_Analyzer(conn); }
};

} } // namespace analyzer::*
