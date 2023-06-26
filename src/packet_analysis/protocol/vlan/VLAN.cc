// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vlan/VLAN.h"

using namespace zeek::packet_analysis::VLAN;

VLANAnalyzer::VLANAnalyzer() : zeek::packet_analysis::Analyzer("VLAN")
	{
	snap_forwarding_key = id::find_val("PacketAnalyzer::VLAN::SNAP_FORWARDING_KEY")->AsCount();
	novell_forwarding_key = id::find_val("PacketAnalyzer::VLAN::NOVELL_FORWARDING_KEY")->AsCount();
	llc_forwarding_key = id::find_val("PacketAnalyzer::VLAN::LLC_FORWARDING_KEY")->AsCount();
	}

bool VLANAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( 4 >= len )
		{
		Weird("truncated_VLAN_header", packet);
		return false;
		}

	auto& vlan_ref = packet->vlan != 0 ? packet->inner_vlan : packet->vlan;
	vlan_ref = ((data[0] << 8u) + data[1]) & 0xfff;

	// Get the protocol/length field from the last 2 bytes of the header.
	uint32_t protocol = ((data[2] << 8u) + data[3]);

	if ( protocol >= 1536 )
		{
		packet->eth_type = protocol;
		// Skip the VLAN header
		return ForwardPacket(len - 4, data + 4, packet, protocol);
		}

	if ( protocol <= 1500 )
		{
		// Skip over the VLAN header
		len -= 4;
		data += 4;

		// Need at least two bytes to check the packet types below.
		if ( len < 2 )
			{
			Weird("truncated_vlan_frame", packet);
			return false;
			}

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

	Weird("undefined_vlan_protocol", packet);
	return false;
	}
