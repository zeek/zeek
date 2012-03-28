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
	/**
	 * Construct an IPv6 header or extension header from assigned type number.
	 */
	IPv6_Hdr(uint8 t, const u_char* d) : type(t), data(d) {}

	/**
	 * Replace the value of the next protocol field.
	 */
	void ChangeNext(uint8 next_type)
		{
		switch ( type ) {
		case IPPROTO_IPV6:
			((ip6_hdr*)data)->ip6_nxt = next_type;
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_AH:
			((ip6_ext*)data)->ip6e_nxt = next_type;
			break;
		case IPPROTO_ESP:
		default:
			break;
		}
		}

	~IPv6_Hdr() {}

	/**
	 * Returns the assigned IPv6 extension header type number of the header
	 * that immediately follows this one.
	 */
	uint8 NextHdr() const
		{
		switch ( type ) {
		case IPPROTO_IPV6:
			return ((ip6_hdr*)data)->ip6_nxt;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_AH:
			return ((ip6_ext*)data)->ip6e_nxt;
		case IPPROTO_ESP:
		default:
			return IPPROTO_NONE;
		}
		}

	/**
	 * Returns the length of the header in bytes.
	 */
	uint16 Length() const
		{
		switch ( type ) {
		case IPPROTO_IPV6:
			return 40;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
			return 8 + 8 * ((ip6_ext*)data)->ip6e_len;
		case IPPROTO_FRAGMENT:
			return 8;
		case IPPROTO_AH:
			return 8 + 4 * ((ip6_ext*)data)->ip6e_len;
		case IPPROTO_ESP:
			return 8; //encrypted payload begins after 8 bytes
		default:
			return 0;
		}
		}

	/**
	 * Returns the RFC 1700 et seq. IANA assigned number for the header.
	 */
	uint8 Type() const { return type; }

	/**
	 * Returns pointer to the start of where header structure resides in memory.
	 */
	const u_char* Data() const { return data; }

	/**
	 * Returns the script-layer record representation of the header.
	 */
	RecordVal* BuildRecordVal(VectorVal* chain = 0) const;

protected:
	uint8 type;
	const u_char* data;
};

class IPv6_Hdr_Chain {
public:
	/**
	 * Initializes the header chain from an IPv6 header structure.
	 */
	IPv6_Hdr_Chain(const struct ip6_hdr* ip6) { Init(ip6, false); }

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

	/**
	 * Returns whether the header chain indicates a fragmented packet.
	 */
	bool IsFragment() const
		{ return chain[chain.size()-1]->Type() == IPPROTO_FRAGMENT; }

	/**
	 * Returns pointer to fragment header structure if the chain contains one.
	 */
	const struct ip6_frag* GetFragHdr() const
		{ return IsFragment() ?
				(const struct ip6_frag*)chain[chain.size()-1]->Data(): 0; }

	/**
	 * If the header chain is a fragment, returns the offset in number of bytes
	 * relative to the start of the Fragmentable Part of the original packet.
	 */
	uint16 FragOffset() const
		{ return IsFragment() ?
				(ntohs(GetFragHdr()->ip6f_offlg) & 0xfff8) : 0; }

	/**
	 * If the header chain is a fragment, returns the identification field.
	 */
	uint32 ID() const
		{ return IsFragment() ?	ntohl(GetFragHdr()->ip6f_ident) : 0; }

	/**
	 * If the header chain is a fragment, returns the M (more fragments) flag.
	 */
	int MF() const
		{ return IsFragment() ?
				(ntohs(GetFragHdr()->ip6f_offlg) & 0x0001) != 0 : 0; }

	/**
	 * Returns whether the chain contains a routing type 0 extension header
	 * with nonzero segments left.
	 */
	bool RH0SegLeft() const
		{
		for ( size_t i = 0; i < chain.size(); ++i )
			if ( chain[i]->Type() == IPPROTO_ROUTING  &&
			     ((const struct ip6_rthdr*)chain[i]->Data())->ip6r_type == 0 &&
			     ((const struct ip6_rthdr*)chain[i]->Data())->ip6r_segleft > 0 )
				return true;
		return false;
		}

	/**
	 * Returns a vector of ip6_ext_hdr RecordVals that includes script-layer
	 * representation of all extension headers in the chain.
	 */
	VectorVal* BuildVal() const;

protected:
	// for access to protected ctor that changes next header values that
	// point to a fragment
	friend class FragReassembler;

	/**
	 * Initializes the header chain from an IPv6 header structure, and replaces
	 * the first next protocol pointer field that points to a fragment header.
	 */
	IPv6_Hdr_Chain(const struct ip6_hdr* ip6, uint16 next)
		{ Init(ip6, true, next); }

	void Init(const struct ip6_hdr* ip6, bool set_next, uint16 next = 0);

	vector<IPv6_Hdr*> chain;
	uint16 length; // The summation of all header lengths in the chain in bytes.
};

class IP_Hdr {
public:
	IP_Hdr(const u_char* p, bool arg_del)
		: ip4(0), ip6(0), del(arg_del), ip6_hdrs(0)
		{
		if ( ((const struct ip*)p)->ip_v == 4 )
			ip4 = (const struct ip*)p;
		else if ( ((const struct ip*)p)->ip_v == 6 )
			{
			ip6 = (const struct ip6_hdr*)p;
			ip6_hdrs = new IPv6_Hdr_Chain(ip6);
			}
		else
			{
			if ( arg_del )
				delete [] p;
			reporter->InternalError("bad IP version in IP_Hdr ctor");
			}
		}

	IP_Hdr(const struct ip* arg_ip4, bool arg_del)
		: ip4(arg_ip4), ip6(0), del(arg_del), ip6_hdrs(0)
		{
		}

	IP_Hdr(const struct ip6_hdr* arg_ip6, bool arg_del,
	       const IPv6_Hdr_Chain* c = 0)
		: ip4(0), ip6(arg_ip6), del(arg_del),
		  ip6_hdrs(c ? c : new IPv6_Hdr_Chain(ip6))
		{
		}

	~IP_Hdr()
		{
		if ( ip6 )
			delete ip6_hdrs;

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

	/**
	 * Returns a pointer to the payload of the IP packet, usually an
	 * upper-layer protocol.
	 */
	const u_char* Payload() const
		{
		if ( ip4 )
			return ((const u_char*) ip4) + ip4->ip_hl * 4;
		else
			return ((const u_char*) ip6) + ip6_hdrs->TotalLength();
		}

	/**
	 * Returns the length of the IP packet's payload (length of packet minus
	 * header length or, for IPv6, also minus length of all extension headers).
	 */
	uint16 PayloadLen() const
		{
		if ( ip4 )
			return ntohs(ip4->ip_len) - ip4->ip_hl * 4;
		else
			return ntohs(ip6->ip6_plen) + 40 - ip6_hdrs->TotalLength();
		}

	/**
	 * Returns the length of the IP packet (length of headers and payload).
	 */
	uint32 TotalLen() const
		{ return ip4 ? ntohs(ip4->ip_len) : ntohs(ip6->ip6_plen) + 40; }

	/**
	 * Returns length of IP packet header (includes extension headers for IPv6).
	 */
	uint16 HdrLen() const
		{ return ip4 ? ip4->ip_hl * 4 : ip6_hdrs->TotalLength(); }

	/**
	 * For IPv6 header chains, returns the type of the last header in the chain.
	 */
	uint8 LastHeader() const
		{ return ip4 ? IPPROTO_RAW :
				((*ip6_hdrs)[ip6_hdrs->Size()-1])->Type(); }

	/**
	 * Returns the protocol type of the IP packet's payload, usually an
	 * upper-layer protocol.  For IPv6, this returns the last (extension)
	 * header's Next Header value.
	 */
	unsigned char NextProto() const
		{ return ip4 ? ip4->ip_p :
				((*ip6_hdrs)[ip6_hdrs->Size()-1])->NextHdr(); }

	unsigned char TTL() const
		{ return ip4 ? ip4->ip_ttl : ip6->ip6_hlim; }

	bool IsFragment() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x3fff) != 0 :
				ip6_hdrs->IsFragment(); }

	/**
	 * Returns the fragment packet's offset in relation to the original
	 * packet in bytes.
	 */
	uint16 FragOffset() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x1fff) * 8 :
				ip6_hdrs->FragOffset(); }

	/**
	 * Returns the fragment packet's identification field.
	 */
	uint32 ID() const
		{ return ip4 ? ntohs(ip4->ip_id) : ip6_hdrs->ID(); }

	/**
	 * Returns whether a fragment packet's "More Fragments" field is set.
	 */
	int MF() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x2000) != 0 : ip6_hdrs->MF(); }

	/**
	 * Returns whether a fragment packet's "Don't Fragment" field is set.
	 * Note that IPv6 has no such field.
	 */
	int DF() const
		{ return ip4 ? ((ntohs(ip4->ip_off) & 0x4000) != 0) : 0; }

	/**
	 * Returns number of IP headers in packet (includes IPv6 extension headers).
	 */
	size_t NumHeaders() const
		{ return ip4 ? 1 : ip6_hdrs->Size(); }

	/**
	 * Returns true if this is an IPv6 header containing a routing type 0
	 * extension with nonzero segments left, else returns false.
	 */
	bool RH0SegLeft() const
		{ return ip4 ? false : ip6_hdrs->RH0SegLeft(); }

	/**
	 * Returns an ip_hdr or ip6_hdr_chain RecordVal.
	 */
	RecordVal* BuildIPHdrVal() const;

	/**
	 * Returns a pkt_hdr RecordVal, which includes not only the IP header, but
	 * also upper-layer (tcp/udp/icmp) headers.
	 */
	RecordVal* BuildPktHdrVal() const;

private:
	const struct ip* ip4;
	const struct ip6_hdr* ip6;
	bool del;
	const IPv6_Hdr_Chain* ip6_hdrs;
};

#endif
