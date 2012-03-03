// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ip_h
#define ip_h

#include "config.h"
#include "net_util.h"
#include "IPAddr.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include <vector>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/**
 * Base class for IPv6 header/extensions.
 */
class IPv6_Hdr {
public:
	IPv6_Hdr() : type(0), data(0) {}

	/**
	 * Construct the main IPv6 header.
	 */
	IPv6_Hdr(const u_char* d) : type(IPPROTO_IPV6), data(d) {}

	/**
	 * Construct an IPv6 header or extension header from assigned type number.
	 */
	IPv6_Hdr(uint8 t, const u_char* d) : type(t), data(d) {}

	virtual ~IPv6_Hdr() {}

	/**
	 * Returns the assigned IPv6 extension header type number of the header
	 * that immediately follows this one.
	 */
	virtual uint8 NextHdr() const { return ((ip6_hdr*)data)->ip6_nxt; }

	/**
	 * Returns the length of the header in bytes.
	 */
	virtual uint16 Length() const { return 40; }

	/**
	 * Returns the RFC 1700 assigned number indicating the header type.
	 */
	uint8 Type() const { return type; }

	/**
	 * Returns the script-layer record representation of the header.
	 */
	virtual RecordVal* BuildRecordVal() const;

protected:
	uint8 type;
	const u_char* data;
};

class IPv6_HopOpts : public IPv6_Hdr {
public:
	IPv6_HopOpts(const u_char* d) : IPv6_Hdr(IPPROTO_HOPOPTS, d) {}
	uint8 NextHdr() const { return ((ip6_ext*)data)->ip6e_nxt; }
	uint16 Length() const { return 8 + 8 * ((ip6_ext*)data)->ip6e_len; }
	RecordVal* BuildRecordVal() const;
};

class IPv6_DstOpts : public IPv6_Hdr {
public:
	IPv6_DstOpts(const u_char* d) : IPv6_Hdr(IPPROTO_DSTOPTS, d) {}
	uint8 NextHdr() const { return ((ip6_ext*)data)->ip6e_nxt; }
	uint16 Length() const { return 8 + 8 * ((ip6_ext*)data)->ip6e_len; }
	RecordVal* BuildRecordVal() const;
};

class IPv6_Routing : public IPv6_Hdr {
public:
	IPv6_Routing(const u_char* d) : IPv6_Hdr(IPPROTO_ROUTING, d) {}
	uint8 NextHdr() const { return ((ip6_ext*)data)->ip6e_nxt; }
	uint16 Length() const { return 8 + 8 * ((ip6_ext*)data)->ip6e_len; }
	RecordVal* BuildRecordVal() const;
};

class IPv6_Fragment : public IPv6_Hdr {
public:
	IPv6_Fragment(const u_char* d) : IPv6_Hdr(IPPROTO_FRAGMENT, d) {}
	uint8 NextHdr() const { return ((ip6_ext*)data)->ip6e_nxt; }
	uint16 Length() const { return 8; }
	RecordVal* BuildRecordVal() const;
};

class IPv6_AH : public IPv6_Hdr {
public:
	IPv6_AH(const u_char* d) : IPv6_Hdr(IPPROTO_AH, d) {}
	uint8 NextHdr() const { return ((ip6_ext*)data)->ip6e_nxt; }
	uint16 Length() const { return 8 + 4 * ((ip6_ext*)data)->ip6e_len; }
	RecordVal* BuildRecordVal() const;
};

class IPv6_ESP : public IPv6_Hdr {
public:
	IPv6_ESP(const u_char* d) : IPv6_Hdr(IPPROTO_ESP, d) {}
	uint8 NextHdr() const { return ((ip6_ext*)data)->ip6e_nxt; }
	// encrypted payload begins after 8 bytes
	uint16 Length() const { return 8; }
	RecordVal* BuildRecordVal() const;
};

class IPv6_Hdr_Chain {
public:
	/**
	 * Initializes the header chain from an IPv6 header structure.
	 */
	IPv6_Hdr_Chain(const struct ip6_hdr* ip6);

	~IPv6_Hdr_Chain()
		{ for ( size_t i = 0; i < chain.size(); ++i ) delete chain[i]; }

	/**
	 * Returns the number of headers in the chain.
	 */
	size_t Size() const { return chain.size(); }

	/**
	 * Returns the sum of the length of all headers in the chain in bytes.
	 */
	uint16 TotalLength() const { return length; }

	/**
	 * Accesses the header at the given location in the chain.
	 */
	const IPv6_Hdr* operator[](const size_t i) const { return chain[i]; }

protected:
	vector<IPv6_Hdr*> chain;
	uint16 length; // The summation of all header lengths in the chain in bytes.
};

class IP_Hdr {
public:
	IP_Hdr(const struct ip* arg_ip4, bool arg_del)
		: ip4(arg_ip4), ip6(0), del(arg_del)
		{
		}

	IP_Hdr(const struct ip6_hdr* arg_ip6, bool arg_del)
		: ip4(0), ip6(arg_ip6), del(arg_del)
		{
		ip6_hdrs = new IPv6_Hdr_Chain(ip6);
		}

	~IP_Hdr()
		{
		if ( ip6 ) delete ip6_hdrs;
		if ( del )
			{
			if ( ip4 )
				delete [] (struct ip*) ip4;
			else
				delete [] (struct ip6_hdr*) ip6;
			}
		}

	//TODO: audit usages of this for correct IPv6 support or IPv4 assumptions
	const struct ip* IP4_Hdr() const	{ return ip4; }

	const struct ip6_hdr* IP6_Hdr() const	{ return ip6; }

	IPAddr SrcAddr() const
		{ return ip4 ? IPAddr(ip4->ip_src) : IPAddr(ip6->ip6_src); }

	IPAddr DstAddr() const
		{ return ip4 ? IPAddr(ip4->ip_dst) : IPAddr(ip6->ip6_dst); }

	const u_char* Payload() const
		{
		if ( ip4 )
			return ((const u_char*) ip4) + ip4->ip_hl * 4;
		else
			return ((const u_char*) ip6) + ip6_hdrs->TotalLength();
		}

	uint16 PayloadLen() const
		{
		if ( ip4 )
			return ntohs(ip4->ip_len) - ip4->ip_hl * 4;
		else
			return ntohs(ip6->ip6_plen) - ip6_hdrs->TotalLength();
		}

	uint16 TotalLen() const
		{ return ip4 ? ntohs(ip4->ip_len) : ntohs(ip6->ip6_plen) + 40; }

	uint16 HdrLen() const
		{ return ip4 ? ip4->ip_hl * 4 : ip6_hdrs->TotalLength(); }

	uint8 LastHeader() const
		{ return ip4 ? IPPROTO_RAW :
				((*ip6_hdrs)[ip6_hdrs->Size()-1])->Type(); }

	unsigned char NextProto() const
		{ return ip4 ? ip4->ip_p :
				((*ip6_hdrs)[ip6_hdrs->Size()-1])->NextHdr(); }

	unsigned char TTL() const
		{ return ip4 ? ip4->ip_ttl : ip6->ip6_hlim; }

	//TODO: check for IPv6 Fragment ext. header
	bool IsFragment() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x3fff) != 0 : false; }

	//TODO: check for IPv6 Fragment ext. header
	uint16 FragOffset() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x1fff) * 8 : 0; }

	//TODO: check for IPv6 Fragment ext. header
	uint16 FragField() const
		{ return ip4 ? ntohs(ip4->ip_off) : 0; }

	//TODO: check for IPv6 Fragment ext. header
	uint16 ID() const
		{ return ip4 ? ntohs(ip4->ip_id) : 0; }

	//TODO: check for IPv6 Fragment ext. header
	int MF() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x2000) != 0 : 0; }

	// IPv6 has no "Don't Fragment" flag.
	int DF() const
		{ return ip4 ? ((ntohs(ip4->ip_off) & 0x4000) != 0) : 0; }

	size_t NumHeaders() const
		{ return ip4 ? 1 : ip6_hdrs->Size(); }

	RecordVal* BuildRecordVal() const;

private:
	const struct ip* ip4;
	const struct ip6_hdr* ip6;
	bool del;
	IPv6_Hdr_Chain* ip6_hdrs;
};

#endif
