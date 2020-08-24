// See the file "COPYING" in the main distribution directory for copyright.

#include <pcap.h>

#include "IEEE802_11_Radio.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::IEEE802_11_Radio;

IEEE802_11_RadioAnalyzer::IEEE802_11_RadioAnalyzer()
	: zeek::packet_analysis::Analyzer("IEEE802_11_Radio")
	{
	}

zeek::packet_analysis::AnalyzerResult IEEE802_11_RadioAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	auto end_of_data = packet->GetEndOfData();

	if ( data + 3 >= end_of_data )
		{
		packet->Weird("truncated_radiotap_header");
		return AnalyzerResult::Failed;
		}

	// Skip over the RadioTap header
	int rtheader_len = (data[3] << 8) + data[2];

	if ( data + rtheader_len >= end_of_data )
		{
		packet->Weird("truncated_radiotap_header");
		return AnalyzerResult::Failed;
		}

	data += rtheader_len;

	return AnalyzeInnerPacket(packet, data, DLT_IEEE802_11);
	}
