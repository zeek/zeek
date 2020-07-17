// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::NFLog {

class NFLogAnalyzer : public Analyzer {
public:
	NFLogAnalyzer();
	~NFLogAnalyzer() override = default;

	AnalysisResultTuple Analyze(Packet* packet, const uint8_t*& data) override;

	static AnalyzerPtr Instantiate()
		{
		return std::make_shared<NFLogAnalyzer>();
		}
};

}
