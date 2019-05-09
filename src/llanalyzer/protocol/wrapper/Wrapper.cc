// See the file "COPYING" in the main distribution directory for copyright.

#include "Wrapper.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::Wrapper;

WrapperAnalyzer::WrapperAnalyzer()
	: zeek::llanalyzer::Analyzer("Wrapper")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> WrapperAnalyzer::Analyze(Packet* packet)
	{
	// Unfortunately some packets on the link might have MPLS labels
	// while others don't. That means we need to ask the link-layer if
	// labels are in place.
	bool have_mpls = false;

	auto pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( pdata[12] == 0x89 && pdata[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( pdata + cfplen + 14 >= end_of_data )
			{
			packet->Weird("truncated_link_header_cfp");
			return { AnalyzerResult::Failed, 0 };
			}

		pdata += cfplen;
		}

	// Extract protocol identifier
	identifier_t protocol = (pdata[12] << 8u) + pdata[13];

	packet->eth_type = protocol;
	packet->l2_dst = pdata;
	packet->l2_src = pdata + 6;

	pdata += 14;

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
				if ( pdata + 4 >= end_of_data )
					{
					packet->Weird("truncated_link_header");
					return { AnalyzerResult::Failed, 0 };
					}

				auto& vlan_ref = saw_vlan ? packet->inner_vlan : packet->vlan;
				vlan_ref = ((pdata[0] << 8u) + pdata[1]) & 0xfff;
				protocol = ((pdata[2] << 8u) + pdata[3]);
				pdata += 4; // Skip the vlan header
				saw_vlan = true;
				packet->eth_type = protocol;
				}
			break;

			// PPPoE carried over the ethernet frame.
			case 0x8864:
				{
				if ( pdata + 8 >= end_of_data )
					{
					packet->Weird("truncated_link_header");
					return { AnalyzerResult::Failed, 0 };
					}

				protocol = (pdata[6] << 8u) + pdata[7];
				pdata += 8; // Skip the PPPoE session and PPP header

				if ( protocol == 0x0021 )
					packet->l3_proto = L3_IPV4;
				else if ( protocol == 0x0057 )
					packet->l3_proto = L3_IPV6;
				else
					{
					// Neither IPv4 nor IPv6.
					packet->Weird("non_ip_packet_in_pppoe_encapsulation");
					return { AnalyzerResult::Failed, 0 };
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
			packet->Weird("non_ip_packet_in_ethernet");
			return { AnalyzerResult::Failed, 0 };
			}
		}

	if ( have_mpls )
		{
		// Skip the MPLS label stack.
		bool end_of_stack = false;

		while ( ! end_of_stack )
			{
			if ( pdata + 4 >= end_of_data )
				{
				packet->Weird("truncated_link_header");
				return { AnalyzerResult::Failed, 0 };
				}

			end_of_stack = *(pdata + 2u) & 0x01;
			pdata += 4;
			}

		// We assume that what remains is IP
		if ( pdata + sizeof(struct ip) >= end_of_data )
			{
			packet->Weird("no_ip_in_mpls_payload");
			return { AnalyzerResult::Failed, 0 };
			}

		const struct ip* ip = (const struct ip*)pdata;

		if ( ip->ip_v == 4 )
			packet->l3_proto = L3_IPV4;
		else if ( ip->ip_v == 6 )
			packet->l3_proto = L3_IPV6;
		else
			{
			// Neither IPv4 nor IPv6.
			packet->Weird("no_ip_in_mpls_payload");
			return { AnalyzerResult::Failed, 0 };
			}
		}

	// Calculate how much header we've used up.
	packet->hdr_size = (pdata - packet->data);

	return { AnalyzerResult::Continue, protocol };
	}
