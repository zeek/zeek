// See the file "COPYING" in the main distribution directory for copyright.

#include "Null.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Null;

NullAnalyzer::NullAnalyzer()
	: zeek::packet_analysis::Analyzer("Null")
	{
	}

zeek::packet_analysis::AnalyzerResult NullAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	if ( data + 4 >= packet->GetEndOfData() )
		{
		packet->Weird("null_analyzer_failed");
		return AnalyzerResult::Failed;
		}

	uint32_t protocol = (data[3] << 24) + (data[2] << 16) + (data[1] << 8) + data[0];
	data += 4; // skip link header

	return AnalyzeInnerPacket(packet, data, protocol);
	}
