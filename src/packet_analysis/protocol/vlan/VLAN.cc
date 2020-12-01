// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vlan/VLAN.h"

using namespace zeek::packet_analysis::VLAN;

VLANAnalyzer::VLANAnalyzer()
	: zeek::packet_analysis::Analyzer("VLAN")
	{
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

	uint32_t protocol = ((data[2] << 8u) + data[3]);
	packet->eth_type = protocol;
	// Skip the VLAN header
	return ForwardPacket(len - 4, data + 4, packet, protocol);
	}
