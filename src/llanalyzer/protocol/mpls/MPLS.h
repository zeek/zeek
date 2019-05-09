// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::MPLS {

class MPLSAnalyzer : public zeek::llanalyzer::Analyzer {
public:
	MPLSAnalyzer();
	~MPLSAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static zeek::llanalyzer::Analyzer* Instantiate()
		{
		return new MPLSAnalyzer();
		}
};

}
