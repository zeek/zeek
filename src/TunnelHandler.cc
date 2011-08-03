// $Id: Sessions.cc 7075 2010-09-13 02:39:38Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.


#include "config.h"

#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

#include "TunnelHandler.h"
#include "Conn.h"
#include "Sessions.h"


TunnelHandler::TunnelHandler(NetSessions *arg_s) 
	{
	s = arg_s;
	}

TunnelInfo* TunnelHandler::DecapsulateTunnel(const IP_Hdr *ip_hdr, int len, int caplen, 
		const struct pcap_pkthdr* hdr, const u_char* const pkt)
	{
	TunnelInfo *tunnel_info = 0;
	switch (ip_hdr->NextProto()) {
#ifdef BROv6
	case IPPROTO_IPV6: /* 6in4  and  6to4 */
		if (len < (int)sizeof(struct ip6_hdr) || caplen < (int)sizeof(struct ip6_hdr))
		{
		s->Weird("truncated_header", hdr, pkt);
		return 0;
		}
		// TODO: check if IP6 header makes sense
		tunnel_info = new TunnelInfo();
		tunnel_info->child = new IP_Hdr((const struct ip6_hdr*)ip_hdr->Payload());
		tunnel_info->tunneltype = BifEnum::IP6inIP;
		tunnel_info->hdr_len = ip_hdr->HdrLen();
		tunnel_info->SetParentIPs(ip_hdr);
		return tunnel_info;
		break;
#endif
	default:
		break;
	} /* end switch */
	return 0;
	}
