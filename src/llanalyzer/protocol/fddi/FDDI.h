// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::FDDI {

class FDDIAnalyzer : public zeek::llanalyzer::Analyzer {
public:
	FDDIAnalyzer();
	~FDDIAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static zeek::llanalyzer::Analyzer* Instantiate()
		{
		return new FDDIAnalyzer();
		}
};

}
