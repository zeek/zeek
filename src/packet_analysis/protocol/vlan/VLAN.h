// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::VLAN {

class VLANAnalyzer : public Analyzer {
public:
	VLANAnalyzer();
	~VLANAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new VLANAnalyzer();
		}
};

}
