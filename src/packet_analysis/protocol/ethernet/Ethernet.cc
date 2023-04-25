// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ethernet/Ethernet.h"

#include "zeek/packet_analysis/Manager.h"

using namespace zeek::packet_analysis::Ethernet;

EthernetAnalyzer::EthernetAnalyzer() : zeek::packet_analysis::Analyzer("Ethernet")
	{
	snap_forwarding_key = id::find_val("PacketAnalyzer::ETHERNET::SNAP_FORWARDING_KEY")->AsCount();
	novell_forwarding_key =
		id::find_val("PacketAnalyzer::ETHERNET::NOVELL_FORWARDING_KEY")->AsCount();
	llc_forwarding_key = id::find_val("PacketAnalyzer::ETHERNET::LLC_FORWARDING_KEY")->AsCount();
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
		len -= 14;
		data += 14;

		if ( len < protocol )
			{
			Weird("truncated_ethernet_frame", packet);
			return false;
			}

		// Let specialized analyzers take over for non Ethernet II frames.
		if ( data[0] == 0xAA && data[1] == 0xAA )
			// IEEE 802.2 SNAP
			return ForwardPacket(len, data, packet, snap_forwarding_key);
		else if ( data[0] == 0xFF && data[1] == 0xFF )
			// Novell raw IEEE 802.3
			return ForwardPacket(len, data, packet, novell_forwarding_key);
		else
			// IEEE 802.2 LLC
			return ForwardPacket(len, data, packet, llc_forwarding_key);
		}

	// Undefined (1500 < EtherType < 1536)
	Weird("undefined_ether_type", packet);
	return false;
	}
