// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ip_h
#define ip_h

#include "config.h"
#include "IPAddr.h"
#include <net_util.h>

class IP_Hdr {
public:
	IP_Hdr(const struct ip* arg_ip4, bool arg_del)
		: ip4(arg_ip4), ip6(0), del(arg_del)
		{
		}

	IP_Hdr(const struct ip6_hdr* arg_ip6, bool arg_del)
		: ip4(0), ip6(arg_ip6), del(arg_del)
		{
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

	IPAddr SrcAddr() const
		{ return ip4 ? IPAddr(ip4->ip_src) : IPAddr(ip6->ip6_src); }
	IPAddr DstAddr() const
		{ return ip4 ? IPAddr(ip4->ip_dst) : IPAddr(ip6->ip6_dst); }

	//TODO: needs adapting/replacement for IPv6 support
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
	bool del;
};

#endif
