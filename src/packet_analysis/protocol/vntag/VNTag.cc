// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vntag/VNTag.h"

using namespace zeek::packet_analysis::VNTag;

VNTagAnalyzer::VNTagAnalyzer() : zeek::packet_analysis::Analyzer("VNTag") { }

bool VNTagAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( 6 >= len )
		{
		Weird("truncated_vntag_header", packet);
		return false;
		}

	uint32_t protocol = ((data[4] << 8u) + data[5]);
	// Skip the VNTag header
	return ForwardPacket(len - 6, data + 6, packet, protocol);
	}
