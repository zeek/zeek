
#include "Packet.h"
#include "Sessions.h"

void Packet::Weird(const char* name)
	{
	sessions->Weird(name, this);
	l2_valid = false;
	}

int Packet::GetLinkHeaderSize(int link_type)
	{
	switch ( link_type ) {
	case DLT_NULL:
		return 4;

	case DLT_EN10MB:
		return 14;

	case DLT_FDDI:
		return 13 + 8;	// fddi_header + LLC

#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		return 16;
#endif

	case DLT_PPP_SERIAL:	// PPP_SERIAL
		return 4;

	case DLT_RAW:
		return 0;
	}

	return -1;
	}

void Packet::ProcessLayer2()
	{
	l2_valid = true;

	// Unfortunately some packets on the link might have MPLS labels
	// while others don't. That means we need to ask the link-layer if
	// labels are in place.
	bool have_mpls = false;

	const u_char* pdata = data;

	switch ( link_type ) {
	case DLT_NULL:
		{
		int protocol = (pdata[3] << 24) + (pdata[2] << 16) + (pdata[1] << 8) + pdata[0];
		pdata += GetLinkHeaderSize(link_type);

		// From the Wireshark Wiki: "AF_INET6, unfortunately, has
		// different values in {NetBSD,OpenBSD,BSD/OS},
		// {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
		// packet might have a link-layer header with 24, 28, or 30
		// as the AF_ value." As we may be reading traces captured on
		// platforms other than what we're running on, we accept them
		// all here.

		if ( protocol == AF_INET )
			l3_proto = L3_IPV4;
		else if ( protocol == 24 || protocol == 28 || protocol == 30 )
			l3_proto = L3_IPV6;
		else
			{
			Weird("non_ip_packet_in_null_transport");
			return;
			}

		break;
		}

	case DLT_EN10MB:
		{
		// Get protocol being carried from the ethernet frame.
		int protocol = (pdata[12] << 8) + pdata[13];
		pdata += GetLinkHeaderSize(link_type);
		eth_type = protocol;

		switch ( protocol )
			{
			// MPLS carried over the ethernet frame.
			case 0x8847:
				have_mpls = true;
				break;

			// VLAN carried over the ethernet frame.
			// 802.1q / 802.1ad
			case 0x8100:
			case 0x9100:
				vlan = ((pdata[0] << 8) + pdata[1]) & 0xfff;
				protocol = ((pdata[2] << 8) + pdata[3]);
				pdata += 4; // Skip the vlan header

				// Check for MPLS in VLAN.
				if ( protocol == 0x8847 )
					{
					have_mpls = true;
					break;
					}

				// Check for double-tagged (802.1ad)
				if ( protocol == 0x8100 || protocol == 0x9100 )
					{
					protocol = ((pdata[2] << 8) + pdata[3]);
					pdata += 4; // Skip the vlan header
					}

				eth_type = protocol;
				break;

			// PPPoE carried over the ethernet frame.
			case 0x8864:
				protocol = (pdata[6] << 8) + pdata[7];
				pdata += 8; // Skip the PPPoE session and PPP header

				if ( protocol == 0x0021 )
					l3_proto = L3_IPV4;
				else if ( protocol == 0x0057 )
					l3_proto = L3_IPV6;
				else
					{
					// Neither IPv4 nor IPv6.
					Weird("non_ip_packet_in_pppoe_encapsulation");
					return;
					}

				break;
			}

		// Normal path to determine Layer 3 protocol.
		if ( ! have_mpls && l3_proto == L3_UNKNOWN )
			{
			if ( protocol == 0x800 )
				l3_proto = L3_IPV4;
			else if ( protocol == 0x86dd )
				l3_proto = L3_IPV6;
			else if ( protocol == 0x0806 || protocol == 0x8035 )
				l3_proto = L3_ARP;
			else
				{
				// Neither IPv4 nor IPv6.
				Weird("non_ip_packet_in_ethernet");
				return;
				}
			}

		break;
		}

	case DLT_PPP_SERIAL:
		{
		// Get PPP protocol.
		int protocol = (pdata[2] << 8) + pdata[3];
		pdata += GetLinkHeaderSize(link_type);

		if ( protocol == 0x0281 )
			{
			// MPLS Unicast. Remove the pdata link layer and
			// denote a header size of zero before the IP header.
			have_mpls = true;
			}
		else if ( protocol == 0x0021 )
			l3_proto = L3_IPV4;
		else if ( protocol == 0x0057 )
			l3_proto = L3_IPV6;
		else
			{
			// Neither IPv4 nor IPv6.
			Weird("non_ip_packet_in_ppp_encapsulation");
			return;
			}
		break;
		}

	default:
		{
		// Assume we're pointing at IP. Just figure out which version.
		pdata += GetLinkHeaderSize(link_type);
		const struct ip* ip = (const struct ip *)pdata;

		if ( ip->ip_v == 4 )
			l3_proto = L3_IPV4;
		else if ( ip->ip_v == 6 )
			l3_proto = L3_IPV6;
		else
			{
			// Neither IPv4 nor IPv6.
			Weird("non_ip_packet");
			return;
			}

		break;
		}
	}

	if ( have_mpls )
		{
		// Skip the MPLS label stack.
		bool end_of_stack = false;

		while ( ! end_of_stack )
			{
			end_of_stack = *(pdata + 2) & 0x01;
			pdata += 4;

			if ( pdata >= pdata + cap_len )
				{
				Weird("no_mpls_payload");
				return;
				}
			}

		// We assume that what remains is IP
		if ( pdata + sizeof(struct ip) >= data + cap_len )
			{
			Weird("no_ip_in_mpls_payload");
			return;
			}

		const struct ip* ip = (const struct ip *)pdata;

		if ( ip->ip_v == 4 )
			l3_proto = L3_IPV4;
		else if ( ip->ip_v == 6 )
			l3_proto = L3_IPV6;
		else
			{
			// Neither IPv4 nor IPv6.
			Weird("no_ip_in_mpls_payload");
			return;
			}
		}

	else if ( encap_hdr_size )
		{
		// Blanket encapsulation. We assume that what remains is IP.
		pdata += encap_hdr_size;
		if ( pdata + sizeof(struct ip) >= data + cap_len )
			{
			Weird("no_ip_left_after_encap");
			return;
			}

		const struct ip* ip = (const struct ip *)pdata;

		if ( ip->ip_v == 4 )
			l3_proto = L3_IPV4;
		else if ( ip->ip_v == 6 )
			l3_proto = L3_IPV6;
		else
			{
			// Neither IPv4 nor IPv6.
			Weird("no_ip_in_encap");
			return;
			}

		}

	// We've now determined (a) L3_IPV4 vs (b) L3_IPV6 vs
	// (c) L3_ARP vs (d) L3_UNKNOWN (0 == anything else)
	l3_proto = l3_proto;

	// Calculate how much header we've used up.
	hdr_size = (pdata - data);
}

