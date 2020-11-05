// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/mpls/MPLS.h"

using namespace zeek::packet_analysis::MPLS;

MPLSAnalyzer::MPLSAnalyzer()
	: zeek::packet_analysis::Analyzer("MPLS")
	{
	}

bool MPLSAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Skip the MPLS label stack.
	bool end_of_stack = false;

	while ( ! end_of_stack )
		{
		if ( 4 >= len )
			{
			Weird("truncated_link_header", packet);
			return false;
			}

		end_of_stack = *(data + 2u) & 0x01;
		data += 4;
		len -= 4;
		}

	// According to RFC3032 the encapsulated protocol is not encoded.
	// We use the configured default analyzer.
	return ForwardPacket(len, data, packet);
	}
