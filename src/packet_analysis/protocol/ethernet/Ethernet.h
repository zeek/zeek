// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::Ethernet {

class EthernetAnalyzer : public Analyzer {
public:
	EthernetAnalyzer();
	~EthernetAnalyzer() override = default;

	AnalysisResultTuple Analyze(Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<EthernetAnalyzer>();
		}
};

}
