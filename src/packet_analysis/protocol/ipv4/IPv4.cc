// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv4.h"

using namespace zeek::packet_analysis::IPv4;

IPv4Analyzer::IPv4Analyzer()
	: zeek::packet_analysis::Analyzer("IPv4")
	{
	}

zeek::packet_analysis::AnalyzerResult IPv4Analyzer::AnalyzePacket(size_t len,
		const uint8_t* data, Packet* packet)
	{
	packet->l3_proto = L3_IPV4;
	packet->hdr_size = static_cast<uint32_t>(data - packet->data);

	// Leave packet analyzer land
	return AnalyzerResult::Terminate;
	}
