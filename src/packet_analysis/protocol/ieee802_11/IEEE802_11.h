// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::IEEE802_11 {

class IEEE802_11Analyzer : public Analyzer {
public:
	IEEE802_11Analyzer();
	~IEEE802_11Analyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<IEEE802_11Analyzer>();
		}
};

}
