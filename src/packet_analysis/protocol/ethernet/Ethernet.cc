// See the file "COPYING" in the main distribution directory for copyright.

#include "Ethernet.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Ethernet;

EthernetAnalyzer::EthernetAnalyzer()
	: zeek::packet_analysis::Analyzer("Ethernet")
	{
	}

zeek::packet_analysis::AnalysisResultTuple EthernetAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	auto end_of_data = packet->GetEndOfData();

	// Make sure that we actually got an entire ethernet header before trying
	// to pull bytes out of it.
	if ( data + 16 >= end_of_data )
		{
		packet->Weird("truncated_ethernet_frame");
		return { AnalyzerResult::Failed, 0 };
		}

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( data[12] == 0x89 && data[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( data + cfplen + 14 >= end_of_data )
			{
			packet->Weird("truncated_link_header_cfp");
			return { AnalyzerResult::Failed, 0 };
			}

		data += cfplen;
		}

	// Get protocol being carried from the ethernet frame.
	uint32_t protocol = (data[12] << 8) + data[13];

	packet->eth_type = protocol;
	packet->l2_dst = data;
	packet->l2_src = data + 6;

	// Ethernet II frames
	if ( protocol >= 1536 )
		{
		data += 14;
		return { AnalyzerResult::Continue, protocol };
		}

	// Other ethernet frame types
	if ( protocol <= 1500 )
		{
		if ( data + 16 >= end_of_data )
			{
			packet->Weird("truncated_ethernet_frame");
			return { AnalyzerResult::Failed, 0 };
			}

		// In the following we use undefined EtherTypes to signal uncommon
		// frame types. This allows specialized analyzers to take over.
		// Note that pdata remains at the start of the ethernet frame.

		// IEEE 802.2 SNAP
		if ( data[14] == 0xAA && data[15] == 0xAA)
			return { AnalyzerResult::Continue, 1502 };

		// Novell raw IEEE 802.3
		if ( data[14] == 0xFF && data[15] == 0xFF)
			return { AnalyzerResult::Continue, 1503 };


		// IEEE 802.2 LLC
		return { AnalyzerResult::Continue, 1501 };
		}

	// Undefined (1500 < EtherType < 1536)
	packet->Weird("undefined_ether_type");
	return { AnalyzerResult::Failed, protocol };
	}
