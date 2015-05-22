// See the file "COPYING" in the main distribution directory for copyright.

#include "L2.h"
#include "IP.h"
#include "Type.h"
#include "Val.h"
#include "Var.h"
#include "NetVar.h"

extern "C" {
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif
}


Val *L2_Hdr::fmt_eui48(const u_char *mac) const
	{
	char buf[20];
	snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return new StringVal(buf);
	}

RecordVal* L2_Hdr::BuildPktHdrVal() const
	{
	static RecordType* l2_hdr_type = 0;
	static RecordType* raw_pkt_hdr_type = 0;

	if ( ! raw_pkt_hdr_type )
		{
		raw_pkt_hdr_type = internal_type("raw_pkt_hdr")->AsRecordType();
		l2_hdr_type = internal_type("l2_hdr")->AsRecordType();
		}

	RecordVal* pkt_hdr = new RecordVal(raw_pkt_hdr_type);
	RecordVal* l2_hdr = new RecordVal(l2_hdr_type);
	int is_ethernet = ( pkt->link_type == DLT_EN10MB ) ? 1 : 0;
	int l3 = BifEnum::layer3_proto::l3_unknown;
	if ( pkt->l3_proto == AF_INET )
		l3 = BifEnum::layer3_proto::l3_ipv4;
	else if ( pkt->l3_proto == AF_INET6 )
		l3 = BifEnum::layer3_proto::l3_ipv6;

	// l2_hdr layout:
	//      encap: link_encap;      ##< L2 link encapsulation
	//	len: count;		##< Total frame length on wire
	//	cap_len: count;		##< Captured length
	//      src: string &optional;  ##< L2 source (if ethernet)
	//      dst: string &optional;  ##< L2 destination (if ethernet)
	//      vlan: count &optional;  ##< VLAN tag if any (and ethernet)
	//	ethertype: count &optional; ##< If ethernet
	//      proto: layer3_proto;    ##< L3 proto
	if ( is_ethernet )
		{
		// Ethernet header layout is:
		//    dst[6bytes] src[6bytes] ethertype[2bytes]...
		l2_hdr->Assign(0, new EnumVal(BifEnum::link_encap::link_ethernet, BifType::Enum::link_encap));
		l2_hdr->Assign(3, fmt_eui48(pkt->data + 6));	// src
		l2_hdr->Assign(4, fmt_eui48(pkt->data));  	// dst
		if ( pkt->vlan )
			l2_hdr->Assign(5, new Val(pkt->vlan, TYPE_COUNT));
		l2_hdr->Assign(6, new Val(pkt->eth_type, TYPE_COUNT));
		if ( pkt->eth_type == ETHERTYPE_ARP || pkt->eth_type == ETHERTYPE_REVARP )
			{
			// We also identify ARP for L3 over ethernet
			l3 = BifEnum::layer3_proto::l3_arp;
			}
		}
	else
		{
		l2_hdr->Assign(0, new EnumVal(BifEnum::link_encap::link_unknown, BifType::Enum::link_encap));
		}
	l2_hdr->Assign(1, new Val(pkt->len, TYPE_COUNT));
	l2_hdr->Assign(2, new Val(pkt->cap_len, TYPE_COUNT));
	l2_hdr->Assign(7, new EnumVal(l3, BifType::Enum::layer3_proto));
	pkt_hdr->Assign(0, l2_hdr);

	if ( pkt->l3_proto == AF_INET )
		{
		IP_Hdr ip_hdr((const struct ip*)(pkt->data + pkt->hdr_size), false);
		return ip_hdr.BuildPktHdrVal(pkt_hdr, 1);
		}
	else if ( pkt->l3_proto == AF_INET6 )
		{
		IP_Hdr ip6_hdr((const struct ip6_hdr*)(pkt->data + pkt->hdr_size), false, pkt->cap_len);
		return ip6_hdr.BuildPktHdrVal(pkt_hdr, 1);
		}
	else
		return pkt_hdr;
	}

