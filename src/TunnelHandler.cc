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
	PortVal *pv = 0;
	TableVal *udp_tunnel_ports = BifConst::Tunnel::udp_tunnel_ports->AsTableVal();
	// Find UDP ports we want to analyze. Store them in an array for faster
	// lookup. 
	for ( int i = 0; i< 65536; i++ )
		{
		if ( pv )
			Unref(pv);
		pv = new PortVal(i, TRANSPORT_UDP);
		if ( udp_tunnel_ports->Lookup(pv, false) )
			udp_ports[i] = 1;
		else 
			udp_ports[i] = 0;
		}
	Unref(pv);
	}

TunnelInfo* TunnelHandler::DecapsulateTunnel(const IP_Hdr *ip_hdr, int len, int caplen, 
		const struct pcap_pkthdr* hdr, const u_char* const pkt)
	{
	TunnelInfo *tunnel_info = 0;
	
	switch ( ip_hdr->NextProto() ) {
	case IPPROTO_IPV6: /* 6in4  and  6to4 */
		if ( BifConst::Tunnel::decapsulate_ip )
			{
			if ( len < (int)sizeof(struct ip6_hdr) ||
			     caplen < (int)sizeof(struct ip6_hdr) )
				{
				s->Weird("truncated_header", hdr, pkt);
				return 0;
				}
			// TODO: check if IP6 header makes sense
			tunnel_info = new TunnelInfo();
			tunnel_info->child = new IP_Hdr((const struct ip6_hdr*)ip_hdr->Payload(), false, caplen);
			tunnel_info->parent.tunneltype = BifEnum::Tunnel::IP6_IN_IP;
			tunnel_info->hdr_len = tunnel_info->child->HdrLen();
			tunnel_info->SetParentIPs(ip_hdr);
			return tunnel_info;
			}
		break;
	// TODO: IP in IP. Find test traces first. IP proto 0 and/or 4
	case IPPROTO_UDP:
		if ( BifConst::Tunnel::decapsulate_udp )
			{
			if ( len < (int)sizeof(struct udphdr) ||
			    caplen < (int)sizeof(struct udphdr) )
				// No weird here. Main packet processing will raise it. 
				return 0;
			return HandleUDP(ip_hdr, len, caplen); 
			}

		break;
	default:
		break;
	} /* end switch */
	return 0;
	}

TunnelInfo* TunnelHandler::HandleUDP(const IP_Hdr *ip_hdr, int len, int caplen)
	{
	// We already know we that we have a valid UDP header
	const u_char *data = ip_hdr->Payload();
	const struct udphdr* uh = (const struct udphdr*)data;
	IP_Hdr *cand_ip_hdr = 0;
	BifEnum::Tunnel::Tunneltype tunneltype = BifEnum::Tunnel::NONE;

	int hdr_len = sizeof(struct udphdr);
	data += hdr_len;

	int datalen = (int)ntohs(uh->uh_ulen);
	datalen = min(datalen, min(len, caplen));
	datalen -= hdr_len;

	if ( BifConst::Tunnel::udp_tunnel_allports || 
			udp_ports[ntohs(uh->uh_sport)] ||
			udp_ports[ntohs(uh->uh_dport)] )
		{
		cand_ip_hdr = LookForIPHdr(data, datalen);
		if ( cand_ip_hdr )
			{
			// Found and IP hdr directly in the UDP payload
			tunneltype =  (cand_ip_hdr->IP4_Hdr()) ? 
					BifEnum::Tunnel::IP4_IN_UDP : BifEnum::Tunnel::IP6_IN_UDP;
			}
		else if ( datalen >= 8 )
			{
			// Look for AYIAY tunnels
			u_char id_byte = data[0];
			u_char sig_byte = data[1];
			u_char next_hdr = data[3];

			// identity length field is high bits of id_byte. 
			// length in octets is 2 to the power of length field
			int id_len = (1 << (id_byte>>4)); 

			// signature length field is high bits of sig_byte
			// length in octets 4 * length field
			int sig_len = 4*(sig_byte>>4);

			datalen -= 8 + id_len + sig_len;
			data += 8 + id_len + sig_len;
			if ( datalen <= 0 )
				return 0;
			cand_ip_hdr = LookForIPHdr(data, datalen);
			if ( cand_ip_hdr )
				{
				hdr_len += 8 + id_len + sig_len;
				tunneltype =  (cand_ip_hdr->IP4_Hdr()) ? 
						BifEnum::Tunnel::IP4_IN_AYIAY : BifEnum::Tunnel::IP6_IN_AYIAY;
				}
			}
		if ( cand_ip_hdr )
			{
			TunnelInfo *tunnel_info = new TunnelInfo();
			tunnel_info->child = cand_ip_hdr;
			tunnel_info->parent.tunneltype =  tunneltype;
			tunnel_info->SetParentIPs(ip_hdr);
			tunnel_info->SetParentPorts(uh);
			tunnel_info->hdr_len = hdr_len + cand_ip_hdr->HdrLen();
			return tunnel_info;
			};
		}
	return 0;
	}

IP_Hdr* TunnelHandler::LookForIPHdr(const u_char *data, int datalen)
	{
	IP_Hdr *cand_ip_hdr = 0;
	if (datalen < (int)sizeof(struct ip))
		return 0;

	const struct ip *ip4 = (const struct ip*)(data);
	if ( ip4->ip_v == 4 )
		cand_ip_hdr = new IP_Hdr((const struct ip*)ip4, false);
	else if ( ip4->ip_v == 6 && (datalen > (int)sizeof(struct ip6_hdr)) )
		cand_ip_hdr = new IP_Hdr((const struct ip6_hdr*)data, false, datalen);

	if ( cand_ip_hdr )
		{
		switch ( cand_ip_hdr->NextProto() ) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
		case IPPROTO_ICMP:
			if ( (int)cand_ip_hdr->TotalLen() != datalen )
				{
				delete cand_ip_hdr;
				cand_ip_hdr = 0;
				}
			break;
		default:
			delete cand_ip_hdr;
			cand_ip_hdr = 0;
			break;
		} // end switch
		}
	return cand_ip_hdr;
	}
