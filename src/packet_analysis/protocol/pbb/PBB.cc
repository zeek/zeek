// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/pbb/PBB.h"

using namespace zeek::packet_analysis::PBB;

PBBAnalyzer::PBBAnalyzer() : zeek::packet_analysis::Analyzer("PBB") { }

bool PBBAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	const uint8_t pbb_header_len = 18;
	const uint8_t etype_offset = pbb_header_len - 2;
	if ( pbb_header_len >= len )
		{
		Weird("truncated_PBB_header", packet);
		return false;
		}

	uint32_t protocol = ((data[etype_offset] << 8u) + data[etype_offset+1]);
	packet->eth_type = protocol;
	// Skip the PBB header
	return ForwardPacket(len - pbb_header_len, data + pbb_header_len, packet, protocol);
	}
