// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/pppoe/PPPoE.h"

using namespace zeek::packet_analysis::PPPoE;

PPPoEAnalyzer::PPPoEAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPoE")
	{
	}

bool PPPoEAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( 8 >= len )
		{
		Weird("truncated_pppoe_header", packet);
		return false;
		}

	// Extract protocol identifier
	uint32_t protocol = (data[6] << 8u) + data[7];
	// Skip the PPPoE session and PPP header
	return ForwardPacket(len - 8, data + 8, packet, protocol);
	}
