// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::PPPoE {

class PPPoEAnalyzer : public Analyzer {
public:
	PPPoEAnalyzer();
	~PPPoEAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new PPPoEAnalyzer();
        }
};

}
