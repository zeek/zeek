// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::IPv6 {

class IPv6Analyzer : public Analyzer {
public:
	IPv6Analyzer();
	~IPv6Analyzer() override = default;

	AnalyzerResult Analyze(Packet* packet, const uint8_t*& data) override;

	static AnalyzerPtr Instantiate()
		{
		return std::make_shared<IPv6Analyzer>();
		}
};

}
