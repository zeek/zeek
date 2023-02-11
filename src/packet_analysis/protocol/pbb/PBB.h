// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

#define PBB_LEN 18u
#define PBB_C_DST_OFF 4u
#define PBB_C_SRC_OFF 10u
#define PBB_ETYPE_OFF 16u


namespace zeek::packet_analysis::PBB
	{

class PBBAnalyzer : public Analyzer
	{
public:
	PBBAnalyzer();
	~PBBAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<PBBAnalyzer>();
		}
	};

	}
