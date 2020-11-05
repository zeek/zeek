// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ieee802_11_radio/IEEE802_11_Radio.h"

#include <pcap.h>

using namespace zeek::packet_analysis::IEEE802_11_Radio;

IEEE802_11_RadioAnalyzer::IEEE802_11_RadioAnalyzer()
	: zeek::packet_analysis::Analyzer("IEEE802_11_Radio")
	{
	}

bool IEEE802_11_RadioAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( 3 >= len )
		{
		Weird("truncated_radiotap_header", packet);
		return false;
		}

	// Skip over the RadioTap header
	size_t rtheader_len = (data[3] << 8) + data[2];

	if ( rtheader_len >= len )
		{
		Weird("truncated_radiotap_header", packet);
		return false;
		}

	return ForwardPacket(len - rtheader_len, data + rtheader_len, packet, DLT_IEEE802_11);
	}
