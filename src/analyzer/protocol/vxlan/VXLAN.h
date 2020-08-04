// See the file  in the main distribution directory for copyright.

#pragma once

#include "analyzer/Analyzer.h"

namespace zeek::analyzer::vxlan {

class VXLAN_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit VXLAN_Analyzer(zeek::Connection* conn)
	    : Analyzer("VXLAN", conn)
		{}

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new VXLAN_Analyzer(conn); }
};

} // namespace zeek::analyzer::vxlan

namespace analyzer::vxlan {

using VXLAN_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::vxlan::VXLAN_Analyzer.")]] = zeek::analyzer::vxlan::VXLAN_Analyzer;

} // namespace analyzer::vxlan
