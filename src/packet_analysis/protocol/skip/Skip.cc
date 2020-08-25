// See the file "COPYING" in the main distribution directory for copyright.

#include "Skip.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Skip;

SkipAnalyzer::SkipAnalyzer()
	: zeek::packet_analysis::Analyzer("Skip")
	{
	}

void SkipAnalyzer::Initialize()
	{
	auto& skip_val = zeek::id::find_val("PacketAnalyzer::SkipAnalyzer::skip_bytes");
	if ( ! skip_val )
		return;

	skip_bytes = skip_val->AsCount();
	}

zeek::packet_analysis::AnalyzerResult SkipAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	data += skip_bytes;
	return AnalyzeInnerPacket(packet, data);
	}
