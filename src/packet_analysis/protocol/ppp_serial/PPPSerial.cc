// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ppp_serial/PPPSerial.h"

using namespace zeek::packet_analysis::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPSerial")
	{
	}

bool PPPSerialAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( 4 >= len )
		{
		Weird("truncated_ppp_serial_header", packet);
		return false;
		}

	// Extract protocol identifier
	uint32_t protocol = (data[2] << 8) + data[3];
	// skip link header
	return ForwardPacket(len - 4, data + 4, packet, protocol);
	}
