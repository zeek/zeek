// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::Wrapper
	{

class WrapperAnalyzer : public Analyzer
	{
public:
	WrapperAnalyzer();
	~WrapperAnalyzer() override = default;

	bool Analyze(Packet* packet, const uint8_t*& data) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<WrapperAnalyzer>();
		}
	};

	}
