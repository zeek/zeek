// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::IPv6 {

class IPv6Analyzer : public Analyzer {
public:
	IPv6Analyzer();
	~IPv6Analyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new IPv6Analyzer();
		}
};

}
