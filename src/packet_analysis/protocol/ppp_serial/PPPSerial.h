// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::PPPSerial
	{

class PPPSerialAnalyzer : public Analyzer
	{
public:
	PPPSerialAnalyzer();
	~PPPSerialAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<PPPSerialAnalyzer>();
		}
	};

	}
