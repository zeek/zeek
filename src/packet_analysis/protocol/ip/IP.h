// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/Frag.h"

namespace zeek::detail { class Discarder; }

namespace zeek::packet_analysis::IP {

class IPAnalyzer : public Analyzer {
public:
	IPAnalyzer();
	~IPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<IPAnalyzer>();
		}

private:

	// Returns a reassembled packet, or nil if there are still
	// some missing fragments.
	zeek::detail::FragReassembler* NextFragment(double t, const IP_Hdr* ip,
	                                            const u_char* pkt);

	zeek::detail::Discarder* discarder = nullptr;
};

}
