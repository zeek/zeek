// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPSerial")
	{
	}

zeek::packet_analysis::AnalyzerResult PPPSerialAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	// Extract protocol identifier
	uint32_t protocol = (data[2] << 8) + data[3];
	data += 4; // skip link header

	return AnalyzeInnerPacket(packet, data, protocol);
	}
