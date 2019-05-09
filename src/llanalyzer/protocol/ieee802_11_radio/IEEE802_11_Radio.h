// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace zeek::llanalyzer::IEEE802_11_Radio {

class IEEE802_11_RadioAnalyzer : public Analyzer {
public:
	IEEE802_11_RadioAnalyzer();
	~IEEE802_11_RadioAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new IEEE802_11_RadioAnalyzer();
		}
};

}
