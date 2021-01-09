// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/skip/Skip.h"

using namespace zeek::packet_analysis::Skip;

SkipAnalyzer::SkipAnalyzer() : zeek::packet_analysis::Analyzer("Skip") { }

void SkipAnalyzer::Initialize()
	{
	Analyzer::Initialize();

	auto& skip_val = zeek::id::find_val("PacketAnalyzer::SKIP::skip_bytes");
	if ( ! skip_val )
		return;

	skip_bytes = skip_val->AsCount();
	}

bool SkipAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	return ForwardPacket(len - skip_bytes, data + skip_bytes, packet);
	}
