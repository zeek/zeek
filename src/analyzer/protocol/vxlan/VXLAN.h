// See the file  in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer::vxlan {

class VXLAN_Analyzer final : public analyzer::Analyzer {
public:
	explicit VXLAN_Analyzer(Connection* conn)
	    : Analyzer("VXLAN", conn)
		{}

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new VXLAN_Analyzer(conn); }
};

} // namespace zeek::analyzer::vxlan

namespace analyzer::vxlan {

using VXLAN_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::vxlan::VXLAN_Analyzer.")]] = zeek::analyzer::vxlan::VXLAN_Analyzer;

} // namespace analyzer::vxlan
