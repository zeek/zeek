#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::PacketDemo {

class Bar : public Analyzer {
public:
	Bar();
	~Bar() override = default;

	AnalyzerResult Analyze(Packet* packet, const uint8_t*& data) override;

	static AnalyzerPtr Instantiate()
		{
		return std::make_shared<Bar>();
		}
};

}
