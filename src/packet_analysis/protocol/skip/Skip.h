// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::Skip {

class SkipAnalyzer : public Analyzer {
public:
	SkipAnalyzer();
	~SkipAnalyzer() override = default;

	void Initialize() override;
	AnalyzerResult Analyze(Packet* packet, const uint8_t*& data) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<SkipAnalyzer>();
		}

private:
	bro_uint_t skip_bytes = 0;
};

}
