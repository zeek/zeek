// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::IPv4 {

class IPv4Analyzer : public Analyzer {
public:
	IPv4Analyzer();
	~IPv4Analyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new IPv4Analyzer();
		}
};

}
