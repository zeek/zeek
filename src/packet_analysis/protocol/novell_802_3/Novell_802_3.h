// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::Novell_802_3
	{

class Novell_802_3Analyzer : public Analyzer
	{
public:
	Novell_802_3Analyzer();
	~Novell_802_3Analyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<Novell_802_3Analyzer>();
		}
	};

	}
