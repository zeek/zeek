// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/pbb/PBB.h"

using namespace zeek::packet_analysis::PBB;

constexpr int PBB_LEN = 18;
constexpr int PBB_C_DST_OFF = 4;

PBBAnalyzer::PBBAnalyzer() : zeek::packet_analysis::Analyzer("PBB") { }

bool PBBAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( PBB_LEN >= len )
		{
		Weird("truncated_PBB_header", packet);
		return false;
		}

	// pass this on to the ethernet analyzer
	return ForwardPacket(len - PBB_C_DST_OFF, data + PBB_C_DST_OFF, packet);
	}
