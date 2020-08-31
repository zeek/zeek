// See the file "COPYING" in the main distribution directory for copyright.

#include "Null.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Null;

NullAnalyzer::NullAnalyzer()
	: zeek::packet_analysis::Analyzer("Null")
	{
	}

zeek::packet_analysis::AnalyzerResult NullAnalyzer::AnalyzePacket(size_t len,
		const uint8_t* data, Packet* packet)
	{
	if ( 4 >= len )
		{
		packet->Weird("null_analyzer_failed");
		return AnalyzerResult::Failed;
		}

	uint32_t protocol = (data[3] << 24) + (data[2] << 16) + (data[1] << 8) + data[0];
	// skip link header
	return ForwardPacket(len - 4, data + 4, packet, protocol);
	}
