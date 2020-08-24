// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::Ethernet {

class EthernetAnalyzer : public Analyzer {
public:
	EthernetAnalyzer();
	~EthernetAnalyzer() override = default;

	void Initialize() override;
	AnalyzerResult Analyze(Packet* packet, const uint8_t*& data) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<EthernetAnalyzer>();
		}

private:
	AnalyzerPtr SNAPAnalyzer = nullptr;
	AnalyzerPtr NovellRawAnalyzer = nullptr;
	AnalyzerPtr LLCAnalyzer = nullptr;

	AnalyzerPtr LoadAnalyzer(const std::string& name);
};

}
