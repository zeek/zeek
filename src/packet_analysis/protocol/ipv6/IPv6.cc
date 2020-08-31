// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv6.h"

using namespace zeek::packet_analysis::IPv6;

IPv6Analyzer::IPv6Analyzer()
	: zeek::packet_analysis::Analyzer("IPv6")
	{
	}

bool IPv6Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	packet->l3_proto = L3_IPV6;
	packet->hdr_size = static_cast<uint32_t>(data - packet->data);
	packet->session_analysis = true;

	// Leave packet analyzer land
	return true;
	}
