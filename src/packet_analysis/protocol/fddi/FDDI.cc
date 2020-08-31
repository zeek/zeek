// See the file "COPYING" in the main distribution directory for copyright.

#include "FDDI.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::FDDI;

FDDIAnalyzer::FDDIAnalyzer()
	: zeek::packet_analysis::Analyzer("FDDI")
	{
	}

bool FDDIAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	size_t hdr_size = 13 + 8; // FDDI header + LLC

	if ( hdr_size >= len )
		{
		packet->Weird("FDDI_analyzer_failed");
		return false;
		}

	// We just skip the header and hope for default analysis
	return ForwardPacket(len - hdr_size, data + hdr_size, packet);
	}
