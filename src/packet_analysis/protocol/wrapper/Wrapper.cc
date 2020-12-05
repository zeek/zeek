// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/wrapper/Wrapper.h"

using namespace zeek::packet_analysis::Wrapper;

WrapperAnalyzer::WrapperAnalyzer()
	: zeek::packet_analysis::Analyzer("Wrapper")
	{
	}

bool WrapperAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	// Unfortunately some packets on the link might have MPLS labels
	// while others don't. That means we need to ask the link-layer if
	// labels are in place.
	bool have_mpls = false;

	auto end_of_data = packet->GetEndOfData();

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( data[12] == 0x89 && data[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( data + cfplen + 14 >= end_of_data )
			{
			Weird("truncated_link_header_cfp", packet);
			return false;
			}

		data += cfplen;
		}

	// Extract protocol identifier
	uint32_t protocol = (data[12] << 8u) + data[13];

	packet->eth_type = protocol;
	packet->l2_dst = data;
	packet->l2_src = data + 6;

	data += 14;

	bool saw_vlan = false;

	while ( protocol == 0x8100 || protocol == 0x9100 ||
	        protocol == 0x8864 )
		{
		switch ( protocol )
			{
			// VLAN carried over the ethernet frame.
			// 802.1q / 802.1ad
			case 0x8100:
			case 0x9100:
				{
				if ( data + 4 >= end_of_data )
					{
					Weird("truncated_link_header", packet);
					return false;
					}

				auto& vlan_ref = saw_vlan ? packet->inner_vlan : packet->vlan;
				vlan_ref = ((data[0] << 8u) + data[1]) & 0xfff;
				protocol = ((data[2] << 8u) + data[3]);
				data += 4; // Skip the vlan header
				saw_vlan = true;
				packet->eth_type = protocol;
				}
			break;

			// PPPoE carried over the ethernet frame.
			case 0x8864:
				{
				if ( data + 8 >= end_of_data )
					{
					Weird("truncated_link_header", packet);
					return false;
					}

				protocol = (data[6] << 8u) + data[7];
				data += 8; // Skip the PPPoE session and PPP header

				if ( protocol == 0x0021 )
					packet->l3_proto = L3_IPV4;
				else if ( protocol == 0x0057 )
					packet->l3_proto = L3_IPV6;
				else
					{
					// Neither IPv4 nor IPv6.
					Weird("non_ip_packet_in_pppoe_encapsulation", packet);
					return false;
					}
				}
			break;
			}
		}

	// Check for MPLS in VLAN.
	if ( protocol == 0x8847 )
		have_mpls = true;

	// Normal path to determine Layer 3 protocol.
	if ( ! have_mpls && packet->l3_proto == L3_UNKNOWN )
		{
		if ( protocol == 0x800 )
			packet->l3_proto = L3_IPV4;
		else if ( protocol == 0x86dd )
			packet->l3_proto = L3_IPV6;
		else if ( protocol == 0x0806 || protocol == 0x8035 )
			packet->l3_proto = L3_ARP;
		else
			{
			// Neither IPv4 nor IPv6.
			Weird("non_ip_packet_in_ethernet", packet);
			return false;
			}
		}

	if ( have_mpls )
		{
		// Skip the MPLS label stack.
		bool end_of_stack = false;

		while ( ! end_of_stack )
			{
			if ( data + 4 >= end_of_data )
				{
				Weird("truncated_link_header", packet);
				return false;
				}

			end_of_stack = *(data + 2u) & 0x01;
			data += 4;
			}

		// We assume that what remains is IP
		if ( data + sizeof(struct ip) >= end_of_data )
			{
			Weird("no_ip_in_mpls_payload", packet);
			return false;
			}

		const struct ip* ip = (const struct ip*)data;

		if ( ip->ip_v == 4 )
			packet->l3_proto = L3_IPV4;
		else if ( ip->ip_v == 6 )
			packet->l3_proto = L3_IPV6;
		else
			{
			// Neither IPv4 nor IPv6.
			Weird("no_ip_in_mpls_payload", packet);
			return false;
			}
		}

	return AnalyzeInnerPacket(packet, data, protocol);
	}
