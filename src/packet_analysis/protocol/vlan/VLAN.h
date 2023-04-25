// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::VLAN
	{

class VLANAnalyzer : public Analyzer
	{
public:
	VLANAnalyzer();
	~VLANAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<VLANAnalyzer>();
		}

private:
	zeek_uint_t snap_forwarding_key = 0;
	zeek_uint_t novell_forwarding_key = 0;
	zeek_uint_t llc_forwarding_key = 0;
	};

	}
