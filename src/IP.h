// $Id: IP.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ip_h
#define ip_h

#include "config.h"

#include <net_util.h>

class IP_Hdr {
public:
	IP_Hdr(struct ip* arg_ip4)
		{
		ip4 = arg_ip4;
		ip6 = 0;
		del = 1;

#ifdef BROv6
		src_addr[0] = src_addr[1] = src_addr[2] = 0;
		dst_addr[0] = dst_addr[1] = dst_addr[2] = 0;

		src_addr[3] = ip4->ip_src.s_addr;
		dst_addr[3] = ip4->ip_dst.s_addr;
#endif
		}

	IP_Hdr(const struct ip* arg_ip4)
		{
		ip4 = arg_ip4;
		ip6 = 0;
		del = 0;

#ifdef BROv6
		src_addr[0] = src_addr[1] = src_addr[2] = 0;
		dst_addr[0] = dst_addr[1] = dst_addr[2] = 0;

		src_addr[3] = ip4->ip_src.s_addr;
		dst_addr[3] = ip4->ip_dst.s_addr;
#endif
		}

	IP_Hdr(struct ip6_hdr* arg_ip6)
		{
		ip4 = 0;
		ip6 = arg_ip6;
		del = 1;

#ifdef BROv6
		memcpy(src_addr, ip6->ip6_src.s6_addr, 16);
		memcpy(dst_addr, ip6->ip6_dst.s6_addr, 16);
#endif
		}

	IP_Hdr(const struct ip6_hdr* arg_ip6)
		{
		ip4 = 0;
		ip6 = arg_ip6;
		del = 0;

#ifdef BROv6
		memcpy(src_addr, ip6->ip6_src.s6_addr, 16);
		memcpy(dst_addr, ip6->ip6_dst.s6_addr, 16);
#endif
		}

	~IP_Hdr()
		{
		if ( del )
			{
			if ( ip4 )
				delete [] (struct ip*) ip4;
			else
				delete [] (struct ip6_hdr*) ip6;
			}
		}

	const struct ip* IP4_Hdr() const	{ return ip4; }
	const struct ip6_hdr* IP6_Hdr() const	{ return ip6; }

#ifdef BROv6
	const uint32* SrcAddr() const	{ return src_addr; }
	const uint32* DstAddr() const	{ return dst_addr; }
#else
	const uint32* SrcAddr() const
		{ return ip4 ? &(ip4->ip_src.s_addr) : 0; }
	const uint32* DstAddr() const
		{ return ip4 ? &(ip4->ip_dst.s_addr) : 0; }
#endif

	uint32 SrcAddr4() const	{ return ip4->ip_src.s_addr; }
	uint32 DstAddr4() const	{ return ip4->ip_dst.s_addr; }

	uint16 ID4() const	{ return ip4 ? ip4->ip_id : 0; }

	const u_char* Payload() const
		{
		if ( ip4 )
			return ((const u_char*) ip4) + ip4->ip_hl * 4;
		else
			return ((const u_char*) ip6) + 40;
		}

	uint16 PayloadLen() const
		{
		if ( ip4 )
			return ntohs(ip4->ip_len) - ip4->ip_hl * 4;
		else
			return ntohs(ip6->ip6_plen);
		}

	uint16 TotalLen() const
		{
		if ( ip4 )
			return ntohs(ip4->ip_len);
		else
			return ntohs(ip6->ip6_plen) + 40;
		}

	uint16 HdrLen() const	{ return ip4 ? ip4->ip_hl * 4 : 40; }
	unsigned char NextProto() const
		{ return ip4 ? ip4->ip_p : ip6->ip6_nxt; }
	unsigned char TTL() const
		{ return ip4 ? ip4->ip_ttl : ip6->ip6_hlim; }
	uint16 FragField() const
		{ return ntohs(ip4 ? ip4->ip_off : 0); }
	int DF() const
		{ return ip4 ? ((ntohs(ip4->ip_off) & IP_DF) != 0) : 0; }
	uint16 IP_ID() const
		{ return ip4 ? (ntohs(ip4->ip_id)) : 0; }

private:
	const struct ip* ip4;
	const struct ip6_hdr* ip6;
#ifdef BROv6
	uint32 src_addr[NUM_ADDR_WORDS];
	uint32 dst_addr[NUM_ADDR_WORDS];
#endif
	int del;
};

#endif
