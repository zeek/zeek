#include "Packet.h"
#include "Sessions.h"
#include "Desc.h"
#include "IP.h"
#include "iosource/Manager.h"

extern "C" {
#include <pcap.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif
}

void Packet::Init(int arg_link_type, pkt_timeval *arg_ts, uint32_t arg_caplen,
		  uint32_t arg_len, const u_char *arg_data, int arg_copy,
		  std::string arg_tag)
	{
	if ( data && copy )
		delete [] data;

	link_type = arg_link_type;
	ts = *arg_ts;
	cap_len = arg_caplen;
	len = arg_len;
	tag = std::move(arg_tag);

	copy = arg_copy;

	if ( arg_data && arg_copy )
		{
		data = new u_char[arg_caplen];
		memcpy(const_cast<u_char *>(data), arg_data, arg_caplen);
		}
	else
		data = arg_data;

	time = ts.tv_sec + double(ts.tv_usec) / 1e6;
	hdr_size = GetLinkHeaderSize(arg_link_type);
	l3_proto = L3_UNKNOWN;
	eth_type = 0;
	vlan = 0;
	inner_vlan = 0;
	l2_src = 0;
	l2_dst = 0;

	l2_valid = false;

	if ( data && cap_len < hdr_size )
		{
		Weird("truncated_link_header");
		return;
		}

	if ( data )
		ProcessLayer2();
	}

const IP_Hdr Packet::IP() const
	{
	return IP_Hdr((struct ip *) (data + hdr_size), false);
	}

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

	case DLT_IEEE802_11:  // 802.11 monitor
		return 34;

	case DLT_IEEE802_11_RADIO:	// 802.11 plus RadioTap
		return 59;

	case DLT_NFLOG:
		// Linux netlink NETLINK NFLOG socket log messages
		// The actual header size is variable, but we return the minimum
		// expected size here, which is 4 bytes for the main header plus at
		// least 2 bytes each for the type and length values assoicated with
		// the final TLV carrying the packet payload.
		return 8;

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
	const u_char* end_of_data = data + cap_len;

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
		// Skip past Cisco FabricPath to encapsulated ethernet frame.
		if ( pdata[12] == 0x89 && pdata[13] == 0x03 )
			{
			auto constexpr cfplen = 16;

			if ( pdata + cfplen + GetLinkHeaderSize(link_type) >= end_of_data )
				{
				Weird("truncated_link_header_cfp");
				return;
				}

			pdata += cfplen;
			}

		// Get protocol being carried from the ethernet frame.
		int protocol = (pdata[12] << 8) + pdata[13];

		eth_type = protocol;
		l2_dst = pdata;
		l2_src = pdata + 6;

		pdata += GetLinkHeaderSize(link_type);

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
						Weird("truncated_link_header");
						return;
						}

					auto& vlan_ref = saw_vlan ? inner_vlan : vlan;
					vlan_ref = ((pdata[0] << 8) + pdata[1]) & 0xfff;
					protocol = ((pdata[2] << 8) + pdata[3]);
					pdata += 4; // Skip the vlan header
					saw_vlan = true;
					eth_type = protocol;
					}
					break;

				// PPPoE carried over the ethernet frame.
				case 0x8864:
					{
					if ( pdata + 8 >= end_of_data )
						{
						Weird("truncated_link_header");
						return;
						}

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
					}
					break;
				}
			}

		// Check for MPLS in VLAN.
		if ( protocol == 0x8847 )
			have_mpls = true;

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

	case DLT_IEEE802_11_RADIO:
		{
		if ( pdata + 3 >= end_of_data )
			{
			Weird("truncated_radiotap_header");
			return;
			}

		// Skip over the RadioTap header
		int rtheader_len = (pdata[3] << 8) + pdata[2];

		if ( pdata + rtheader_len >= end_of_data )
			{
			Weird("truncated_radiotap_header");
			return;
			}

		pdata += rtheader_len;
		// fallthrough
		}

	case DLT_IEEE802_11:
		{
		u_char len_80211 = 24; // minimal length of data frames

		if ( pdata + len_80211 >= end_of_data )
			{
			Weird("truncated_802_11_header");
			return;
			}

		u_char fc_80211 = pdata[0]; // Frame Control field

		// Skip non-data frame types (management & control).
		if ( ! ((fc_80211 >> 2) & 0x02) )
			return;

		// Skip subtypes without data.
		if ( (fc_80211 >> 4) & 0x04 )
			return;

		// 'To DS' and 'From DS' flags set indicate use of the 4th
		// address field.
		if ( (pdata[1] & 0x03) == 0x03 )
			len_80211 += l2_addr_len;

		// Look for the QoS indicator bit.
		if ( (fc_80211 >> 4) & 0x08 )
			{
			// Skip in case of A-MSDU subframes indicated by QoS
			// control field.
			if ( pdata[len_80211] & 0x80)
				return;

			len_80211 += 2;
			}

		if ( pdata + len_80211 >= end_of_data )
			{
			Weird("truncated_802_11_header");
			return;
			}

		// Determine link-layer addresses based
		// on 'To DS' and 'From DS' flags
		switch ( pdata[1] & 0x03 ) {
			case 0x00:
				l2_src = pdata + 10;
				l2_dst = pdata + 4;
				break;

			case 0x01:
				l2_src = pdata + 10;
				l2_dst = pdata + 16;
				break;

			case 0x02:
				l2_src = pdata + 16;
				l2_dst = pdata + 4;
				break;

			case 0x03:
				l2_src = pdata + 24;
				l2_dst = pdata + 16;
				break;
		}

		// skip 802.11 data header
		pdata += len_80211;

		if ( pdata + 8 >= end_of_data )
			{
			Weird("truncated_802_11_header");
			return;
			}
		// Check that the DSAP and SSAP are both SNAP and that the control
		// field indicates that this is an unnumbered frame.
		// The organization code (24bits) needs to also be zero to
		// indicate that this is encapsulated ethernet.
		if ( pdata[0] == 0xAA && pdata[1] == 0xAA && pdata[2] == 0x03 &&
		     pdata[3] == 0 && pdata[4] == 0 && pdata[5] == 0 )
			{
			pdata += 6;
			}
		else
			{
			// If this is a logical link control frame without the
			// possibility of having a protocol we care about, we'll
			// just skip it for now.
			return;
			}

		int protocol = (pdata[0] << 8) + pdata[1];
		if ( protocol == 0x0800 )
			l3_proto = L3_IPV4;
		else if ( protocol == 0x86DD )
			l3_proto = L3_IPV6;
		else if ( protocol == 0x0806 || protocol == 0x8035 )
			l3_proto = L3_ARP;
		else
			{
			Weird("non_ip_packet_in_ieee802_11");
			return;
			}
		pdata += 2;

		break;
		}

	case DLT_NFLOG:
		{
		// See https://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html

		uint8_t protocol = pdata[0];

		if ( protocol == AF_INET )
			l3_proto = L3_IPV4;
		else if ( protocol == AF_INET6 )
			l3_proto = L3_IPV6;
		else
			{
			Weird("non_ip_in_nflog");
			return;
			}

		uint8_t version = pdata[1];

		if ( version != 0 )
			{
			Weird("unknown_nflog_version");
			return;
			}

		// Skip to TLVs.
		pdata += 4;

		uint16_t tlv_len;
		uint16_t tlv_type;

		while ( true )
			{
			if ( pdata + 4 >= end_of_data )
				{
				Weird("nflog_no_pcap_payload");
				return;
				}

			// TLV Type and Length values are specified in host byte order
			// (libpcap should have done any needed byteswapping already).

			tlv_len = *(reinterpret_cast<const uint16_t*>(pdata));
			tlv_type = *(reinterpret_cast<const uint16_t*>(pdata + 2));

			auto constexpr nflog_type_payload = 9;

			if ( tlv_type == nflog_type_payload )
				{
				// The raw packet payload follows this TLV.
				pdata += 4;
				break;
				}
			else
				{
				// The Length value includes the 4 octets for the Type and
				// Length values, but TLVs are also implicitly padded to
				// 32-bit alignments (that padding may not be included in
				// the Length value).

				if ( tlv_len < 4 )
					{
					Weird("nflog_bad_tlv_len");
					return;
					}
				else
					{
					auto rem = tlv_len % 4;

					if ( rem != 0 )
						tlv_len += 4 - rem;
					}

				pdata += tlv_len;
				}
			}

		break;
		}

	default:
		{
		// Assume we're pointing at IP. Just figure out which version.
		pdata += GetLinkHeaderSize(link_type);
		if ( pdata + sizeof(struct ip) >= end_of_data )
			{
			Weird("truncated_link_header");
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
			if ( pdata + 4 >= end_of_data )
				{
				Weird("truncated_link_header");
				return;
				}

			end_of_stack = *(pdata + 2) & 0x01;
			pdata += 4;
			}

		// We assume that what remains is IP
		if ( pdata + sizeof(struct ip) >= end_of_data )
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
		if ( pdata + encap_hdr_size + sizeof(struct ip) >= end_of_data )
			{
			Weird("no_ip_left_after_encap");
			return;
			}

		pdata += encap_hdr_size;

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

	// We've now determined (a) L3_IPV4 vs (b) L3_IPV6 vs (c) L3_ARP vs
	// (d) L3_UNKNOWN.

	// Calculate how much header we've used up.
	hdr_size = (pdata - data);
}

RecordVal* Packet::BuildPktHdrVal() const
	{
	RecordVal* pkt_hdr = new RecordVal(raw_pkt_hdr_type);
	RecordVal* l2_hdr = new RecordVal(l2_hdr_type);

	int is_ethernet = (link_type == DLT_EN10MB) ? 1 : 0;

	int l3 = BifEnum::L3_UNKNOWN;

	if ( l3_proto == L3_IPV4 )
		l3 = BifEnum::L3_IPV4;

	else if ( l3_proto == L3_IPV6 )
		l3 = BifEnum::L3_IPV6;

	else if ( l3_proto == L3_ARP )
		l3 = BifEnum::L3_ARP;

	// l2_hdr layout:
	//      encap: link_encap;      ##< L2 link encapsulation
	//      len: count;		##< Total frame length on wire
	//      cap_len: count;		##< Captured length
	//      src: string &optional;  ##< L2 source (if ethernet)
	//      dst: string &optional;  ##< L2 destination (if ethernet)
	//      vlan: count &optional;  ##< VLAN tag if any (and ethernet)
	//      inner_vlan: count &optional;  ##< Inner VLAN tag if any (and ethernet)
	//      ethertype: count &optional; ##< If ethernet
	//      proto: layer3_proto;    ##< L3 proto

	if ( is_ethernet )
		{
		// Ethernet header layout is:
		//    dst[6bytes] src[6bytes] ethertype[2bytes]...
		l2_hdr->Assign(0, BifType::Enum::link_encap->GetVal(BifEnum::LINK_ETHERNET));
		l2_hdr->Assign(3, FmtEUI48(data + 6));	// src
		l2_hdr->Assign(4, FmtEUI48(data));  	// dst

		if ( vlan )
			l2_hdr->Assign(5, val_mgr->GetCount(vlan));

		if ( inner_vlan )
			l2_hdr->Assign(6, val_mgr->GetCount(inner_vlan));

		l2_hdr->Assign(7, val_mgr->GetCount(eth_type));

		if ( eth_type == ETHERTYPE_ARP || eth_type == ETHERTYPE_REVARP )
			// We also identify ARP for L3 over ethernet
			l3 = BifEnum::L3_ARP;
		}
	else
		l2_hdr->Assign(0, BifType::Enum::link_encap->GetVal(BifEnum::LINK_UNKNOWN));

	l2_hdr->Assign(1, val_mgr->GetCount(len));
	l2_hdr->Assign(2, val_mgr->GetCount(cap_len));

	l2_hdr->Assign(8, BifType::Enum::layer3_proto->GetVal(l3));

	pkt_hdr->Assign(0, l2_hdr);

	if ( l3_proto == L3_IPV4 )
		{
		IP_Hdr ip_hdr((const struct ip*)(data + hdr_size), false);
		return ip_hdr.BuildPktHdrVal(pkt_hdr, 1);
		}

	else if ( l3_proto == L3_IPV6 )
		{
		IP_Hdr ip6_hdr((const struct ip6_hdr*)(data + hdr_size), false, cap_len);
		return ip6_hdr.BuildPktHdrVal(pkt_hdr, 1);
		}

	else
		return pkt_hdr;
	}

Val *Packet::FmtEUI48(const u_char *mac) const
	{
	char buf[20];
	snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return new StringVal(buf);
	}

void Packet::Describe(ODesc* d) const
	{
	const IP_Hdr ip = IP();
	d->Add(ip.SrcAddr());
	d->Add("->");
	d->Add(ip.DstAddr());
	}

