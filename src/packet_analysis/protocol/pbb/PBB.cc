// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/pbb/PBB.h"

using namespace zeek::packet_analysis::PBB;

PBBAnalyzer::PBBAnalyzer() : zeek::packet_analysis::Analyzer("PBB") { }

bool PBBAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( PBB_LEN >= len )
		{
		Weird("truncated_PBB_header", packet);
		return false;
		}

	uint32_t protocol = ((data[PBB_ETYPE_OFF] << 8u) + data[PBB_ETYPE_OFF + 1u]);
	packet->eth_type = protocol;
	packet->l2_dst = data + PBB_C_DST_OFF;
	packet->l2_src = data + PBB_C_SRC_OFF;
	// Skip the PBB header
	return ForwardPacket(len - PBB_LEN, data + PBB_LEN, packet, protocol);
	}
