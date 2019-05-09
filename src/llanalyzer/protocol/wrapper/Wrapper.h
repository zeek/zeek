// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::Wrapper {

class WrapperAnalyzer : public Analyzer {
public:
	WrapperAnalyzer();
	~WrapperAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new WrapperAnalyzer();
		}
};

}
