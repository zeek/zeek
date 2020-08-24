// See the file "COPYING" in the main distribution directory for copyright.

#include "FDDI.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::FDDI;

FDDIAnalyzer::FDDIAnalyzer()
	: zeek::packet_analysis::Analyzer("FDDI")
	{
	}

zeek::packet_analysis::AnalyzerResult FDDIAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	auto hdr_size = 13 + 8; // FDDI header + LLC

	if ( data + hdr_size >= packet->GetEndOfData() )
		{
		packet->Weird("FDDI_analyzer_failed");
		return AnalyzerResult::Failed;
		}

	// We just skip the header and hope for default analysis
	data += hdr_size;
	return AnalyzeInnerPacket(packet, data);
	}
