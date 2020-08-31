// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPoE.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPoE;

PPPoEAnalyzer::PPPoEAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPoE")
	{
	}

zeek::packet_analysis::AnalyzerResult PPPoEAnalyzer::AnalyzePacket(size_t len,
		const uint8_t* data, Packet* packet)
	{
	if ( 8 >= len )
		{
		packet->Weird("truncated_pppoe_header");
		return AnalyzerResult::Failed;
		}

	// Extract protocol identifier
	uint32_t protocol = (data[6] << 8u) + data[7];
	// Skip the PPPoE session and PPP header
	return ForwardPacket(len - 8, data + 8, packet, protocol);
	}
