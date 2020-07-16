// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::IPv4 {

class IPv4Analyzer : public Analyzer {
public:
	IPv4Analyzer();
	~IPv4Analyzer() override = default;

	AnalysisResultTuple Analyze(Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<IPv4Analyzer>();
		}
};

}
