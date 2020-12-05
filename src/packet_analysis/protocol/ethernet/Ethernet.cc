// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ethernet/Ethernet.h"
#include "zeek/packet_analysis/Manager.h"

using namespace zeek::packet_analysis::Ethernet;

EthernetAnalyzer::EthernetAnalyzer()
	: zeek::packet_analysis::Analyzer("Ethernet")
	{
	}

void EthernetAnalyzer::Initialize()
	{
	Analyzer::Initialize();

	SNAPAnalyzer = LoadAnalyzer("snap_analyzer");
	NovellRawAnalyzer = LoadAnalyzer("novell_raw_analyzer");
	LLCAnalyzer = LoadAnalyzer("llc_analyzer");
	}

bool EthernetAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Make sure that we actually got an entire ethernet header before trying
	// to pull bytes out of it.
	if ( 16 >= len )
		{
		Weird("truncated_ethernet_frame", packet);
		return false;
		}

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( data[12] == 0x89 && data[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( cfplen + 14 >= len )
			{
			Weird("truncated_link_header_cfp", packet);
			return false;
			}

		data += cfplen;
		len -= cfplen;
		}

	// Get protocol being carried from the ethernet frame.
	uint32_t protocol = (data[12] << 8) + data[13];

	packet->eth_type = protocol;
	packet->l2_dst = data;
	packet->l2_src = data + 6;

	// Ethernet II frames
	if ( protocol >= 1536 )
		return ForwardPacket(len - 14, data + 14, packet, protocol);

	// Other ethernet frame types
	if ( protocol <= 1500 )
		{
		if ( 16 >= len )
			{
			Weird("truncated_ethernet_frame", packet);
			return false;
			}

		// Let specialized analyzers take over for non Ethernet II frames.
		// Note that pdata remains at the start of the ethernet frame.

		AnalyzerPtr eth_analyzer = nullptr;

		if ( data[14] == 0xAA && data[15] == 0xAA)
			// IEEE 802.2 SNAP
			eth_analyzer = SNAPAnalyzer;
		else if ( data[14] == 0xFF && data[15] == 0xFF)
			// Novell raw IEEE 802.3
			eth_analyzer = NovellRawAnalyzer;
		else
			// IEEE 802.2 LLC
			eth_analyzer = LLCAnalyzer;

		if ( eth_analyzer )
			return eth_analyzer->AnalyzePacket(len, data, packet);

		return true;
		}

	// Undefined (1500 < EtherType < 1536)
	Weird("undefined_ether_type", packet);
	return false;
	}
